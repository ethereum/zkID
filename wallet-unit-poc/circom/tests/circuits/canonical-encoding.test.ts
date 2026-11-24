import assert from "assert";
import type { WitnessTester } from "circomkit";
import { circomkit } from "../common/index.ts";

/**
 * Regression tests for the two encoding-alias findings:
 *
 *  - CheckBytesInRangeP256: BytesToNumberBE(32) reduces mod P, so `x` and
 *    `x + P` are distinct 32-byte encodings that collapse onto one field
 *    element. Key coordinates must be pinned to the canonical encoding.
 *
 *  - ClaimValueNormalizer string format: big-endian packing erases leading
 *    zero bytes, so "\0A" packs identically to "A".
 */

const P = BigInt(
  "0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
);

function toBytes32(v: bigint): number[] {
  const out = new Array(32).fill(0);
  let x = v;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

describe("CheckBytesInRangeP256", () => {
  let circuit: WitnessTester<["in"], []>;

  before(async () => {
    circuit = await circomkit.WitnessTester("CheckBytesInRangeP256", {
      file: "utils/utils",
      template: "CheckBytesInRangeP256",
      params: [32],
      recompile: true,
    });
  });

  it("accepts a canonical coordinate", async () => {
    // P-256 generator x.
    const gx = BigInt(
      "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    );
    await circuit.expectConstraintPass(
      await circuit.calculateWitness({ in: toBytes32(gx) }),
    );
  });

  it("accepts P-1, the largest canonical value", async () => {
    await circuit.expectConstraintPass(
      await circuit.calculateWitness({ in: toBytes32(P - 1n) }),
    );
  });

  it("rejects exactly P, which aliases onto zero", async () => {
    await circuit.expectFail({ in: toBytes32(P) });
  });

  it("rejects P+1, which aliases onto one", async () => {
    await circuit.expectFail({ in: toBytes32(P + 1n) });
  });

  it("rejects the all-ones encoding", async () => {
    await circuit.expectFail({ in: new Array(32).fill(255) });
  });
});

describe("ClaimValueNormalizer rejects leading-NUL strings", () => {
  const VALUE_LEN = 32;
  const STRING_FORMAT = 4;
  /** Explicit NUL; a literal one in the source is invisible and easy to mangle. */
  const NUL = String.fromCharCode(0);
  let circuit: WitnessTester<["value", "valueLength", "format", "isActive"], ["normalizedValue"]>;

  before(async () => {
    circuit = await circomkit.WitnessTester("ClaimValueNormalizer", {
      file: "components/claim-value-normalizer",
      template: "ClaimValueNormalizer",
      params: [VALUE_LEN],
      recompile: true,
    });
  });

  function stringInput(s: string) {
    const bytes = Array.from(s, (c) => c.charCodeAt(0));
    return {
      value: [...bytes, ...Array(VALUE_LEN - bytes.length).fill(0)],
      valueLength: bytes.length,
      format: STRING_FORMAT,
      isActive: 1,
    };
  }

  it("packs a normal string and still round-trips", async () => {
    const witness = await circuit.calculateWitness(stringInput("admin"));
    await circuit.expectConstraintPass(witness);
    const out = await circuit.readWitnessSignals(witness, ["normalizedValue"]);
    // "admin" big-endian packed.
    const expected = Array.from("admin").reduce(
      (acc, c) => acc * 256n + BigInt(c.charCodeAt(0)),
      0n,
    );
    assert.strictEqual(BigInt(out.normalizedValue as string | bigint), expected);
  });

  it("rejects a leading NUL that would alias onto the shorter string", async () => {
    // "\0admin" packs to the same integer as "admin".
    await circuit.expectFail(stringInput(NUL + "admin"));
  });

  it("rejects a lone NUL that would collide with the empty string", async () => {
    await circuit.expectFail(stringInput(NUL));
  });

  it("still accepts the empty string", async () => {
    await circuit.expectConstraintPass(
      await circuit.calculateWitness(stringInput("")),
    );
  });
});
