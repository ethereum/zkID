import { describe, expect, it } from "vitest";
import { InputError } from "../src/errors.js";
import { JWT_PARAMS_BY_SIZE, selectVcSizeForSigningInput } from "../src/sizing.js";
import { sha256Pad } from "../src/utils.js";

const profiles = [
  { size: "1k", lastFitting: 1271, paddedLength: 1280 },
  { size: "2k", lastFitting: 1975, paddedLength: 1984 },
  { size: "4k", lastFitting: 4023, paddedLength: 4032 },
  { size: "8k", lastFitting: 8119, paddedLength: 8128 },
] as const;

describe("JWT signing length profile boundaries", () => {
  it.each(profiles)(
    "selects and pads $size at its last fitting signing length",
    ({ size, lastFitting, paddedLength }) => {
      const message = new Uint8Array(lastFitting).fill(65);
      const selected = selectVcSizeForSigningInput(message.length);
      const { maxMessageLength } = JWT_PARAMS_BY_SIZE[selected];

      expect(selected).toBe(size);
      expect(sha256Pad(message, maxMessageLength)[1]).toBe(paddedLength);
    },
  );

  it.each([
    { signingLength: 1272, expectedSize: "2k" },
    { signingLength: 1976, expectedSize: "4k" },
    { signingLength: 4024, expectedSize: "8k" },
  ])(
    "selects $expectedSize for $signingLength signing bytes so the padded length fits",
    ({ signingLength, expectedSize }) => {
      expect(selectVcSizeForSigningInput(signingLength)).toBe(expectedSize);
    },
  );

  it("rejects 8,120 signing bytes because the padded length exceeds the largest profile's circuit bound", () => {
    expect(() => selectVcSizeForSigningInput(8120)).toThrow(InputError);
  });
});
