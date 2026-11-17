import type { WitnessTester } from "circomkit";
import { p256 } from "@noble/curves/nist.js";
import assert from "assert";
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
