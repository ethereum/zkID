import assert from "assert";
import { changedLeafCount, issuerMirrorBytes, mirrorMinBytes, mirrorUpdateBytes, proofFetchBytes } from "../../scripts/benchmarks/registry-bandwidth.ts";

const leaf = (value: bigint, nextValue: bigint) => ({ value, nextValue });

describe("registry update bandwidth", () => {
  it("counts new leaves and predecessors whose next pointer moved", () => {
    const before = [leaf(0n, 10n), leaf(10n, 0n)];
    // 5 sits between the sentinel and 10: one new leaf, one rewritten predecessor.
    const after = [leaf(0n, 5n), leaf(10n, 0n), leaf(5n, 10n)];
    assert.strictEqual(changedLeafCount(before, after), 2);
  });

  it("counts no change for identical states", () => {
    const s = [leaf(0n, 10n), leaf(10n, 0n)];
    assert.strictEqual(changedLeafCount(s, s), 0);
  });

  it("sizes a mirror update as 64-byte leaf records plus a 32-byte root", () => {
    assert.strictEqual(mirrorUpdateBytes(2), 2 * 64 + 32);
    assert.strictEqual(mirrorUpdateBytes(0), 32);
  });

  it("sizes a fetched proof as siblings, leaf, index and root", () => {
    assert.strictEqual(proofFetchBytes("revocation", 20), 20 * 32 + 64 + 4 + 32);
    assert.strictEqual(proofFetchBytes("issuer", 8), 8 * 32 + 32 + 4 + 32);
  });

  it("sizes the minimum mirror update as one 32-byte value per update plus the root", () => {
    assert.strictEqual(mirrorMinBytes(100), 100 * 32 + 32);
  });

  it("gives 324 bytes for an issuer proof at the 256-leaf, depth-8 population", () => {
    assert.strictEqual(proofFetchBytes("issuer", 8), 324);
  });

  it("sizes an issuer mirror update as 32-byte leaves plus the root", () => {
    assert.strictEqual(issuerMirrorBytes(1), 64);
  });
});
