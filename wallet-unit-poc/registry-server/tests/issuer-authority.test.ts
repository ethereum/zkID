import { IssuerRegistry, sha256Hash2, sha256Scheme } from "@coordination-network/issuer-registry";
import { beforeEach, describe, expect, it } from "vitest";

import { IssuerRegistryAuthority, RegistryError } from "../src/index.js";

const issuerKey = (n: number) => sha256Hash2(BigInt(n), BigInt(n) + 1n);

describe("IssuerRegistryAuthority", () => {
  let now: number;
  let authority: IssuerRegistryAuthority;

  beforeEach(() => {
    now = 1_000;
    authority = new IssuerRegistryAuthority({ rootDuration: 60, clock: () => now });
  });

  it("builds the same tree as a SHA-256 IssuerRegistry", () => {
    const commitments = [1, 2, 3].map(issuerKey);
    authority.addIssuers(commitments);

    const mirror = new IssuerRegistry(commitments, sha256Scheme);
    expect(authority.root).toBe(mirror.root);
    expect(IssuerRegistry.fromLeaves(authority.leaves, sha256Scheme).root).toBe(authority.root);
    expect(IssuerRegistry.verifyProof(authority.generateProof(commitments[1]!), sha256Scheme)).toBe(true);
  });

  it("never accepts the empty root", () => {
    expect(authority.root).toBe(0n);
    expect(authority.isValidRoot(0n)).toBe(false);

    authority.addIssuer(issuerKey(1));
    authority.removeIssuer(issuerKey(1));
    expect(authority.root).toBe(0n);
    expect(authority.isValidRoot(0n)).toBe(false);
  });

  it("keeps a superseded root valid for rootDuration seconds, strictly", () => {
    authority.addIssuer(issuerKey(1));
    const first = authority.root;
    authority.addIssuer(issuerKey(2));

    expect(authority.isValidRoot(authority.root)).toBe(true);
    now += 59;
    expect(authority.isValidRoot(first)).toBe(true);
    now += 1;
    expect(authority.isValidRoot(first)).toBe(false);
    expect(authority.isValidRoot(authority.root)).toBe(true);
  });

  it("expireRoots rejects every superseded root but not later ones", () => {
    authority.addIssuer(issuerKey(1));
    const first = authority.root;
    authority.addIssuer(issuerKey(2));
    const second = authority.root;

    authority.expireRoots();
    expect(authority.isValidRoot(first)).toBe(false);
    expect(authority.isValidRoot(second)).toBe(true);

    authority.removeIssuer(issuerKey(1));
    expect(authority.isValidRoot(second)).toBe(true);
    expect(authority.isValidRoot(first)).toBe(false);
  });

  it("after expireRoots, a root superseded in the same second is only valid if it was current at the expiry", () => {
    authority.addIssuer(issuerKey(1));
    const a = authority.root;
    now += 10;

    // Expiry, then a to b and b to c, all in the same second.
    authority.expireRoots();
    authority.addIssuer(issuerKey(2));
    const b = authority.root;
    authority.addIssuer(issuerKey(3));

    expect(authority.isValidRoot(a)).toBe(true);
    expect(authority.isValidRoot(b)).toBe(false);

    // A root superseded after the expiry second gets the usual grace.
    now += 1;
    const c = authority.root;
    authority.addIssuer(issuerKey(4));
    expect(authority.isValidRoot(c)).toBe(true);
    expect(authority.isValidRoot(b)).toBe(false);
  });

  it("rejects a root superseded in the expiry second before the expiry", () => {
    authority.addIssuer(issuerKey(1));
    now += 10;
    const a = authority.root;
    authority.addIssuer(issuerKey(2));
    authority.expireRoots();
    expect(authority.isValidRoot(a)).toBe(false);
  });

  it("clears the stamp of a root that becomes current again", () => {
    authority.addIssuer(issuerKey(1));
    const a = authority.root;
    authority.updateIssuerCommitment(issuerKey(1), issuerKey(2));
    authority.updateIssuerCommitment(issuerKey(2), issuerKey(1));
    expect(authority.root).toBe(a);

    now += 3_600;
    expect(authority.isValidRoot(a)).toBe(true);
  });

  it("rejects adds past maxDepth and leaves the tree unchanged", () => {
    const small = new IssuerRegistryAuthority({ maxDepth: 2, clock: () => now });
    small.addIssuers([1, 2, 3, 4].map(issuerKey));
    const root = small.root;

    expect(() => small.addIssuer(issuerKey(5))).toThrowError(
      expect.objectContaining({ code: "MAX_DEPTH_EXCEEDED" }),
    );
    expect(small.root).toBe(root);
    expect(small.size).toBe(4);
    expect(small.isIssuer(issuerKey(5))).toBe(false);
  });

  it("addIssuers is all or nothing", () => {
    authority.addIssuer(issuerKey(1));
    const root = authority.root;

    expect(() => authority.addIssuers([issuerKey(2), issuerKey(1)])).toThrow(RegistryError);
    expect(authority.root).toBe(root);
    expect(authority.isIssuer(issuerKey(2))).toBe(false);
  });

  it("round-trips through toJSON and fromJSON", () => {
    authority.addIssuers([1, 2, 3].map(issuerKey));
    const old = authority.root;
    authority.removeIssuer(issuerKey(2));

    const restored = IssuerRegistryAuthority.fromJSON(JSON.parse(JSON.stringify(authority.toJSON())), {
      clock: () => now,
    });
    expect(restored.root).toBe(authority.root);
    expect(restored.leaves).toEqual(authority.leaves);
    expect(restored.rootDuration).toBe(60);
    expect(restored.isValidRoot(old)).toBe(true);
  });

  it("keeps a root expiry across toJSON and fromJSON", () => {
    authority.addIssuer(issuerKey(1));
    const a = authority.root;
    authority.addIssuer(issuerKey(2));
    authority.expireRoots();
    authority.addIssuer(issuerKey(3));
    const b = authority.root;
    now += 1;
    authority.addIssuer(issuerKey(4));

    const restored = IssuerRegistryAuthority.fromJSON(JSON.parse(JSON.stringify(authority.toJSON())), {
      clock: () => now,
    });
    for (const root of [a, b]) expect(restored.isValidRoot(root)).toBe(authority.isValidRoot(root));
    expect(restored.isValidRoot(a)).toBe(false);
  });

  it("rejects a tampered snapshot", () => {
    authority.addIssuers([1, 2].map(issuerKey));
    const state = authority.toJSON();
    // The snapshot is the tree's levels, leaves first and the root last.
    const levels: string[][] = JSON.parse(state.tree);
    levels[levels.length - 1]![0] = issuerKey(9).toString();
    const tree = levels;
    expect(() => IssuerRegistryAuthority.fromJSON({ ...state, tree: JSON.stringify(tree) })).toThrow();
  });
});
