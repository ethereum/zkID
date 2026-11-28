import { describe, it, expect } from "vitest";
import { createHash } from "crypto";
import { p256 } from "@noble/curves/nist.js";

import { issuerCommitment } from "../src/index.js";

const { x, y } = p256.Point.BASE.multiply(3n).toAffine();
const ISSUER = { x, y };
const P256_P = p256.CURVE.p;

const be32 = (v: bigint) => Buffer.from(v.toString(16).padStart(64, "0"), "hex");

const sha256Words = (...words: bigint[]) =>
  BigInt("0x" + createHash("sha256").update(Buffer.concat(words.map(be32))).digest("hex"));

describe("issuer commitments", () => {
  it("is sha256(be32(x) || be32(y) || be32(2))", () => {
    expect(issuerCommitment(ISSUER)).toBe(sha256Words(ISSUER.x, ISSUER.y, 2n));
  });

  it("differs from the internal-node hash sha256(be32(x) || be32(y))", () => {
    expect(issuerCommitment(ISSUER)).not.toBe(sha256Words(ISSUER.x, ISSUER.y));
  });

  it("rejects a point off P-256 or with a coordinate not below p", () => {
    expect(() => issuerCommitment({ x: ISSUER.x, y: ISSUER.y + 1n })).toThrow(/P-256/);
    expect(() => issuerCommitment({ x: ISSUER.x + P256_P, y: ISSUER.y })).toThrow(/P-256/);
  });
});
