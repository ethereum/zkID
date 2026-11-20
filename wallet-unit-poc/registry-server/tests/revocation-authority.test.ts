import { PROOF_TYPE, RevocationRegistry, sha256Scheme } from "@coordination-network/revocation-registry";
import { beforeEach, describe, expect, it } from "vitest";

import { RevocationRegistryAuthority } from "../src/index.js";

const forbidden = expect.objectContaining({ code: "FORBIDDEN" });

describe("RevocationRegistryAuthority", () => {
  let now: number;
  let authority: RevocationRegistryAuthority;

  beforeEach(() => {
    now = 1_000;
    authority = new RevocationRegistryAuthority({ rootDuration: 60, clock: () => now });
    authority.setRevoker("issuer-a", true);
    authority.setRevoker("issuer-b", true);
  });

  it("builds the same tree as a SHA-256 RevocationRegistry", () => {
    authority.revokeMany("issuer-a", [30n, 10n]);
    authority.revoke("issuer-b", 20n);

    const mirror = new RevocationRegistry([30n, 10n, 20n], sha256Scheme);
    expect(authority.root).toBe(mirror.root);
    expect(RevocationRegistry.fromLeaves(authority.leafSlots, sha256Scheme).root).toBe(authority.root);

    const proof = mirror.generateProof(15n);
    expect(proof.proofType).toBe(PROOF_TYPE.NON_MEMBERSHIP);
    expect(authority.generateProof(10n).proofType).toBe(PROOF_TYPE.MEMBERSHIP);
  });

  it("accepts the empty root while current and for rootDuration after the first revocation", () => {
    expect(authority.isValidRoot(0n)).toBe(true);
    authority.revoke("issuer-a", 1n);
    now += 59;
    expect(authority.isValidRoot(0n)).toBe(true);
    now += 1;
    expect(authority.isValidRoot(0n)).toBe(false);
  });

  it("only authorized revokers can revoke", () => {
    expect(() => authority.revoke("unknown", 1n)).toThrowError(forbidden);
    authority.setRevoker("issuer-a", false);
    expect(() => authority.revoke("issuer-a", 1n)).toThrowError(forbidden);
  });

  it("only the revoker that revoked a commitment can unrevoke or update it", () => {
    authority.revoke("issuer-a", 5n);
    expect(authority.revokedBy(5n)).toBe("issuer-a");

    expect(() => authority.unrevoke("issuer-b", 5n)).toThrowError(forbidden);
    expect(() => authority.updateRevocationCommitment("issuer-b", 5n, 6n)).toThrowError(forbidden);

    authority.updateRevocationCommitment("issuer-a", 5n, 6n);
    expect(authority.isRevoked(5n)).toBe(false);
    expect(authority.revokedBy(6n)).toBe("issuer-a");

    authority.unrevoke("issuer-a", 6n);
    expect(authority.isRevoked(6n)).toBe(false);
    expect(authority.revokedBy(6n)).toBeUndefined();
  });

  it("a deauthorized revoker keeps its revocations but cannot undo them", () => {
    authority.revoke("issuer-a", 5n);
    authority.setRevoker("issuer-a", false);
    expect(authority.isRevoked(5n)).toBe(true);
    expect(() => authority.unrevoke("issuer-a", 5n)).toThrowError(forbidden);
  });

  it("revokeMany is all or nothing", () => {
    authority.revoke("issuer-a", 5n);
    const root = authority.root;

    expect(() => authority.revokeMany("issuer-b", [7n, 5n])).toThrow();
    expect(authority.root).toBe(root);
    expect(authority.isRevoked(7n)).toBe(false);
    expect(authority.revokedBy(7n)).toBeUndefined();

    expect(() => authority.revokeMany("issuer-b", [8n, 8n])).toThrow();
    expect(authority.isRevoked(8n)).toBe(false);
  });

  it("accepts revocations past the Show circuit's depth, as on chain", () => {
    // 1024 slots (sentinel plus 1023) is depth 10; one more revocation makes it 11.
    authority.revokeMany("issuer-a", Array.from({ length: 1024 }, (_, i) => BigInt(i + 1)));
    expect(authority.depth).toBe(11);
    expect(authority.isRevoked(1024n)).toBe(true);
  });

  it("rejects zero and values of 2^256 or more", () => {
    expect(() => authority.revoke("issuer-a", 0n)).toThrowError(expect.objectContaining({ code: "INVALID_INPUT" }));
    expect(() => authority.revoke("issuer-a", 1n << 256n)).toThrowError(
      expect.objectContaining({ code: "INVALID_INPUT" }),
    );
  });

  it("round-trips through toJSON and fromJSON, tombstones included", () => {
    authority.revokeMany("issuer-a", [3n, 1n, 2n]);
    authority.unrevoke("issuer-a", 1n);
    const old = authority.root;
    authority.revoke("issuer-b", 9n);

    const restored = RevocationRegistryAuthority.fromJSON(JSON.parse(JSON.stringify(authority.toJSON())), {
      clock: () => now,
    });
    expect(restored.root).toBe(authority.root);
    expect(restored.leafSlots).toEqual(authority.leafSlots);
    expect(restored.revokedBy(9n)).toBe("issuer-b");
    expect(restored.isRevoker("issuer-a")).toBe(true);
    expect(restored.isValidRoot(old)).toBe(true);
  });
});
