import { strict as assert } from "assert";
import type { WitnessTester } from "circomkit";
import { circomkit } from "../common/index.ts";

const VALUE_LEN = 96;
const FORMAT_BOOL = 0n;
const FORMAT_UINT = 1n;
const FORMAT_ISO_DATE = 2n;
const FORMAT_ROC_DATE = 3n;

function formatInput(text: string, format: bigint) {
  const value = new Array<bigint>(VALUE_LEN).fill(0n);
  for (let i = 0; i < text.length; i++) value[i] = BigInt(text.charCodeAt(i));
  return { value, valueLength: BigInt(text.length), format };
}

function uintInput(decimal: string) {
  return formatInput(decimal, FORMAT_UINT);
}

// The circuits compile over secq256r1 (circomkit.json), whose modulus is the
// P-256 base field. A decimal at or past 78 digits wraps the uint accumulator.
const q = 115792089210356248762697446949407573530086143415290314195533631308867097853951n;

describe("ClaimValueNormalizer uint range", () => {
  let circuit: WitnessTester<["value", "valueLength", "format"], ["normalizedValue"]>;

  before(async () => {
    circuit = await circomkit.WitnessTester("claim_value_normalizer", {
      file: "components/claim-value-normalizer",
      template: "ClaimValueNormalizer",
      params: [VALUE_LEN],
      recompile: true,
    });
  });

  it("normalizes an ordinary uint", async () => {
    await circuit.expectPass(uintInput("18"), { normalizedValue: 18n });
  });

  it("normalizes the largest accepted uint", async () => {
    const d = "9".repeat(19);
    await circuit.expectPass(uintInput(d), { normalizedValue: BigInt(d) });
  });

  it("rejects a decimal that overflows the predicate domain", async () => {
    // 10^19 > 2^64, so this can no longer reach LessEqThan(64).
    await circuit.expectFail(uintInput("1".repeat(20)));
  });

  it("rejects a field-wrapping decimal that would alias onto a small residue", async () => {
    // A 78-digit value congruent to 17 mod q. Verified: before the length
    // bound this normalized to exactly 17, satisfying a `claim <= 18`
    // predicate that is false for the actual signed decimal.
    const aliased = q + 17n;
    assert.ok(aliased % q === 17n);
    assert.ok(aliased.toString().length <= VALUE_LEN);
    await circuit.expectFail(uintInput(aliased.toString()));
  });

  it("rejects a non-digit byte under uint format", async () => {
    await circuit.expectFail(uintInput("1a3"));
  });

  it("rejects a byte just outside the digit range", async () => {
    await circuit.expectFail(uintInput("1:3")); // ':' is '9' + 1
  });

  // The extractor zero-masks past valueLength, so an under-length date makes
  // every unread slot contribute (0 - 48) = q - 48. Before the width and digit
  // checks these normalized to ~q, which satisfies LessEqThan(64) against every
  // comparison value -- i.e. every `birth_date <= cutoff` policy proved true.
  it("normalizes a well-formed ISO date", async () => {
    await circuit.expectPass(formatInput("2010-01-01", FORMAT_ISO_DATE), {
      normalizedValue: 20100101n,
    });
  });

  it("normalizes a well-formed ROC date", async () => {
    await circuit.expectPass(formatInput("0900101", FORMAT_ROC_DATE), {
      normalizedValue: 900101n,
    });
  });

  it("rejects an empty ISO date", async () => {
    // Normalized to q - 533333328 before the fix.
    await circuit.expectFail(formatInput("", FORMAT_ISO_DATE));
  });

  it("rejects an empty ROC date", async () => {
    await circuit.expectFail(formatInput("", FORMAT_ROC_DATE));
  });

  it("rejects a short ISO date", async () => {
    await circuit.expectFail(formatInput("2010-01-0", FORMAT_ISO_DATE));
  });

  it("rejects an over-long value under ROC date format", async () => {
    // The refute6-datefmt PoC: an ordinary signed phone number read as a date.
    await circuit.expectFail(formatInput("+886912345678", FORMAT_ROC_DATE));
  });

  it("rejects a non-digit byte inside a correctly sized ISO date", async () => {
    await circuit.expectFail(formatInput("2010-01-0a", FORMAT_ISO_DATE));
  });

  it("rejects a sub-'0' byte inside a correctly sized ROC date", async () => {
    await circuit.expectFail(formatInput("090+101", FORMAT_ROC_DATE));
  });

  it("rejects a wrong separator byte in an ISO date", async () => {
    await circuit.expectFail(formatInput("2010/01/01", FORMAT_ISO_DATE));
    await circuit.expectFail(formatInput("2010-01/01", FORMAT_ISO_DATE));
    await circuit.expectFail(formatInput("2010/01-01", FORMAT_ISO_DATE));
  });

  it("does not constrain the ROC date, which has no separators", async () => {
    await circuit.expectPass(formatInput("0900101", FORMAT_ROC_DATE), {
      normalizedValue: 900101n,
    });
  });

  it("rejects an empty uint", async () => {
    // Normalized to 0 before the fix, satisfying any zero-favorable policy.
    await circuit.expectFail(uintInput(""));
  });

  it("still accepts a uint of one or more digits", async () => {
    await circuit.expectPass(uintInput("100"), { normalizedValue: 100n });
    await circuit.expectPass(uintInput("0"), { normalizedValue: 0n });
  });

  describe("bool", () => {
    for (const [text, expected] of [
      ["1", 1n],
      ["true", 1n],
      ["0", 0n],
      ["false", 0n],
    ] as const) {
      it(`accepts ${text}`, async () => {
        await circuit.expectPass(formatInput(text, FORMAT_BOOL), { normalizedValue: expected });
      });
    }

    for (const text of ["banana", "", "2", "True", "tru", "falsy", "00", "10", "truee", "fals"]) {
      it(`rejects ${JSON.stringify(text)}`, async () => {
        // Normalized to 0 before the fix, satisfying a false-favorable policy.
        await circuit.expectFail(formatInput(text, FORMAT_BOOL));
      });
    }
  });
});
