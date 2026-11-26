import type { WitnessTester } from "circomkit";
import { circomkit } from "../common/index.ts";
import assert from "assert";

describe("HashModScalarField", () => {
  let circuit!: WitnessTester<["hash"], ["out"]>;

  const p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFn;
  const q = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551n;

  async function hashModOutput(digest: bigint): Promise<bigint> {
    const hash = digest.toString(2).padStart(256, "0").split("").map(Number);
    const witness = await circuit.calculateWitness({ hash });
    await circuit.expectConstraintPass(witness);
    const { "main.out": out } = await circuit.readWitness(witness, ["main.out"]);
    return out;
  }

  before(async () => {
    circuit = await circomkit.WitnessTester("HashModScalarField", {
      file: "utils/utils",
      template: "HashModScalarField",
      params: [],
      recompile: true,
    });

    console.log("#constraints:", await circuit.getConstraintCount());
  });

  it("agrees with direct scalar reduction at q-1, q, q+1, and p-1", async () => {
    for (const digest of [q - 1n, q, q + 1n, p - 1n]) {
      assert.strictEqual(await hashModOutput(digest), digest % q, `digest = ${digest}`);
    }
  });

  for (const [label, digest] of [
    ["p", p],
    ["p+1", p + 1n],
    ["the largest 256-bit digest", (1n << 256n) - 1n],
  ] as const) {
    it(`agrees with direct scalar reduction at ${label}`, async () => {
      assert.strictEqual(await hashModOutput(digest), digest % q, `digest = ${digest}`);
    });
  }
});
