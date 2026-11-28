import type { WitnessTester } from "circomkit";
import { p256 } from "@noble/curves/nist.js";
import assert from "assert";
import { createHash } from "crypto";
import { circomkit } from "../common/index.ts";
import {
  buildIssuerRegistry,
  generateIssuerMembershipInputs,
  issuerCommitment,
  toLimbs,
  type IssuerKeyPoint,
} from "../../src/issuer-hiding.ts";

const MAX_DEPTH = 3;

const randomIssuer = (): IssuerKeyPoint => {
  const { x, y } = p256.Point.fromAffine(p256.Point.BASE.multiply(BigInt(1 + Math.floor(Math.random() * 1e9))).toAffine());
  return { x, y };
};

describe("IssuerMembership (SHA-256 LeanIMT)", () => {
  let circuit: WitnessTester<
    ["pubKeyX", "pubKeyY", "depth", "index", "siblings"],
    ["root"]
  >;
  const issuers = Array.from({ length: 5 }, randomIssuer);
  const registry = buildIssuerRegistry(issuers);

  const inputsFor = (issuer: IssuerKeyPoint) => {
    const m = generateIssuerMembershipInputs(issuer, registry, MAX_DEPTH);
    return {
      pubKeyX: m.issuerKeyX,
      pubKeyY: m.issuerKeyY,
      depth: m.issuerTreeDepth,
      index: m.issuerTreeIndex,
      siblings: m.issuerTreeSiblings,
    };
  };

  before(async () => {
    circuit = await circomkit.WitnessTester("IssuerMembership", {
      file: "components/issuer-membership",
      template: "IssuerMembership",
      params: [MAX_DEPTH],
      recompile: true,
    });
    console.log("#constraints:", await circuit.getConstraintCount());
  });

  it("outputs the registry root for every issuer", async () => {
    for (const issuer of issuers) {
      await circuit.expectPass(inputsFor(issuer), { root: toLimbs(registry.root) });
    }
  });

  it("outputs the leaf itself for a one-issuer registry", async () => {
    const issuer = issuers[0]!;
    await circuit.expectPass(
      { pubKeyX: issuer.x, pubKeyY: issuer.y, depth: 0, index: 0, siblings: Array(MAX_DEPTH).fill([0, 0]) },
      { root: toLimbs(issuerCommitment(issuer)) }
    );
  });

  it("hashes the leaf as sha256(be32(x) || be32(y) || be32(2))", () => {
    const issuer = issuers[0]!;
    const be32 = (v: bigint) => Buffer.from(v.toString(16).padStart(64, "0"), "hex");
    const digest = (...words: bigint[]) =>
      BigInt("0x" + createHash("sha256").update(Buffer.concat(words.map(be32))).digest("hex"));
    assert.strictEqual(issuerCommitment(issuer), digest(issuer.x, issuer.y, 2n));
    assert.notStrictEqual(issuerCommitment(issuer), digest(issuer.x, issuer.y));
  });

  it("gives a different root for a key outside the registry", async () => {
    const outsider = randomIssuer();
    const w = await circuit.calculateWitness({ ...inputsFor(issuers[1]!), pubKeyX: outsider.x, pubKeyY: outsider.y });
    const { root } = await circuit.readWitnessSignals(w, ["root"]);
    assert.notDeepStrictEqual(root, toLimbs(registry.root));
  });

  it("rejects a zero key coordinate", async () => {
    await circuit.expectFail({ ...inputsFor(issuers[0]!), pubKeyX: 0 });
  });

  it("rejects a depth above the maximum", async () => {
    await circuit.expectFail({ ...inputsFor(issuers[0]!), depth: MAX_DEPTH + 1 });
  });
});

describe("BitsBelowFieldModulus", () => {
  // P-256 base prime, the secq256r1 field modulus.
  const P = BigInt("0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
  const leBits = (v: bigint) => Array.from({ length: 256 }, (_, i) => Number((v >> BigInt(i)) & 1n));
  let circuit: WitnessTester<["in"], []>;

  before(async () => {
    circuit = await circomkit.WitnessTester("BitsBelowFieldModulus", {
      file: "components/issuer-membership",
      template: "BitsBelowFieldModulus",
      recompile: true,
    });
  });

  for (const [name, value] of [
    ["0", 0n],
    ["1", 1n],
    ["the generator x", p256.Point.BASE.x],
    ["2^255", 1n << 255n],
    ["p - 1", P - 1n],
    ["p - 2^96", P - (1n << 96n)],
  ] as const) {
    it(`accepts ${name}`, async () => {
      await circuit.expectConstraintPass(await circuit.calculateWitness({ in: leBits(value) }));
    });
  }

  for (const [name, value] of [
    ["p", P],
    ["p + 1", P + 1n],
    ["x + p for a small x", 5n + P],
    ["2^256 - 1", (1n << 256n) - 1n],
    ["p + 2^191, setting a bit p has clear", P + (1n << 191n)],
  ] as const) {
    it(`rejects ${name}`, async () => {
      await circuit.expectFail({ in: leBits(value) });
    });
  }
});
