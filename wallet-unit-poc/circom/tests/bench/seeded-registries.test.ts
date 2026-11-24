import assert from "assert";
import { buildSeededIssuerRegistry, buildSeededRevocationRegistry, parseSeededFlags, seededCommitments } from "../../src/seeded-registries.ts";
import { DEFAULT_TEST_ISSUER, issuerCommitment } from "../../src/issuer-hiding.ts";

describe("seeded registries", () => {
  it("derives the same commitments for the same seed and differs across seeds", () => {
    assert.deepStrictEqual(seededCommitments("rev", 7, 4), seededCommitments("rev", 7, 4));
    assert.notDeepStrictEqual(seededCommitments("rev", 7, 4), seededCommitments("rev", 8, 4));
    assert.notDeepStrictEqual(seededCommitments("rev", 7, 4), seededCommitments("iss", 7, 4));
  });

  it("builds revocation registries with a reproducible root and the requested size", () => {
    const a = buildSeededRevocationRegistry(100, 1);
    const b = buildSeededRevocationRegistry(100, 1);
    assert.strictEqual(a.root, b.root);
    assert.strictEqual(a.size, 100);
    assert.notStrictEqual(a.root, buildSeededRevocationRegistry(100, 2).root);
  });

  it("puts the real issuer in a registry of the requested size", () => {
    const reg = buildSeededIssuerRegistry(DEFAULT_TEST_ISSUER, 256, 1);
    assert.strictEqual(reg.size, 256);
    assert.strictEqual(reg.depth, 8);
    assert.strictEqual(reg.generateProof(issuerCommitment(DEFAULT_TEST_ISSUER)).siblings.length, 8);
    assert.strictEqual(reg.root, buildSeededIssuerRegistry(DEFAULT_TEST_ISSUER, 256, 1).root);
  });

  it("starts seeded mode only for --issuers, --revoked or --seed", () => {
    assert.strictEqual(parseSeededFlags(["--size", "2k", "--out", "x.json"]), undefined);
    assert.deepStrictEqual(parseSeededFlags(["--revoked", "9"]), { issuers: 256, revoked: 9, seed: 1 });
    assert.deepStrictEqual(parseSeededFlags(["--seed", "3", "--out", "x"]), { issuers: 256, revoked: 5, seed: 3 });
  });
});
