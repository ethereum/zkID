import type { WitnessTester } from "circomkit";
import { p256 } from "@noble/curves/nist.js";
import assert from "assert";
import { circomkit } from "../common/index.ts";
import { issuerKeyBits } from "../../src/revocation.ts";

// P-256 base prime, the secq256r1 field modulus.
const P = BigInt("0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");

describe("IssuerKeyBits", () => {
  let circuit: WitnessTester<["pubKeyX", "pubKeyY"], ["out"]>;

  before(async () => {
    circuit = await circomkit.WitnessTester("IssuerKeyBits", {
      file: "components/issuer-key",
      template: "IssuerKeyBits",
    });
  });

  it("outputs be32(x) || be32(y) as big-endian bits", async () => {
    const { x, y } = p256.Point.BASE.multiply(7n).toAffine();
    const bits = (v: bigint) => v.toString(2).padStart(256, "0").split("").map(BigInt);
    const w = await circuit.calculateWitness({ pubKeyX: x, pubKeyY: y });
    const { out } = await circuit.readWitnessSignals(w, ["out"]);
    assert.deepStrictEqual(out, [...bits(x), ...bits(y)]);
    assert.deepStrictEqual(out, issuerKeyBits({ x, y }).map(BigInt));
  });

  it("rejects a zero coordinate", async () => {
    await circuit.expectFail({ pubKeyX: 0n, pubKeyY: p256.Point.BASE.y });
  });
});

describe("BitsBelowFieldModulus", () => {
  const leBits = (v: bigint) => Array.from({ length: 256 }, (_, i) => Number((v >> BigInt(i)) & 1n));
  let circuit: WitnessTester<["in"], []>;

  before(async () => {
    circuit = await circomkit.WitnessTester("BitsBelowFieldModulus", {
      file: "components/issuer-key",
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
