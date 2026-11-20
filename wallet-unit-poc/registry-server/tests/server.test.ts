import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { IssuerRegistry, sha256Hash2, sha256Scheme } from "@coordination-network/issuer-registry";
import { PROOF_TYPE } from "@coordination-network/revocation-registry";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  createRegistryServer,
  FileStore,
  RegistryClient,
  RegistryClientError,
  type IssuerAuthorityState,
  type RegistryServer,
  type RevocationServiceState,
  type StateStore,
} from "../src/index.js";

const ISSUER_OWNER = "issuer-owner-token-0123456789";
const REVOCATION_OWNER = "revocation-owner-token-0123456789";

const issuerKey = (n: number) => sha256Hash2(BigInt(n), BigInt(n) + 1n);

async function rejection(promise: Promise<unknown>): Promise<RegistryClientError> {
  const error = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(RegistryClientError);
  return error as RegistryClientError;
}

describe("registry server", () => {
  let now: number;
  let dir: string;
  let registry: RegistryServer;
  let url: string;

  async function start(): Promise<void> {
    registry = await createRegistryServer({
      issuer: {
        ownerToken: ISSUER_OWNER,
        store: new FileStore<IssuerAuthorityState>(join(dir, "issuer.json")),
        rootDuration: 60,
      },
      revocation: {
        ownerToken: REVOCATION_OWNER,
        store: new FileStore<RevocationServiceState>(join(dir, "revocation.json")),
        rootDuration: 60,
      },
      clock: () => now,
    });
    url = await registry.listen(0);
  }

  beforeEach(async () => {
    now = 1_000;
    dir = await mkdtemp(join(tmpdir(), "openac-registries-"));
    await start();
  });

  afterEach(async () => {
    await registry.close();
    await rm(dir, { recursive: true, force: true });
  });

  it("serves the issuer registry to holders and verifiers", async () => {
    const owner = new RegistryClient(url, { token: ISSUER_OWNER });
    const commitments = [1, 2, 3].map(issuerKey);
    const root = await owner.addIssuers(commitments);

    const holder = new RegistryClient(url);
    const mirror = await holder.syncIssuerRegistry();
    expect(mirror.root).toBe(root);
    const proof = mirror.generateProof(commitments[2]!);
    expect(IssuerRegistry.verifyProof(proof, sha256Scheme)).toBe(true);

    const verifier = new RegistryClient(url);
    expect(await verifier.isValidIssuerRoot(proof.root)).toBe(true);
    expect(await verifier.isValidIssuerRoot(0n)).toBe(false);
    expect(await verifier.isIssuer(commitments[0]!)).toBe(true);
  });

  it("removes a compromised issuer and expires old roots", async () => {
    const owner = new RegistryClient(url, { token: ISSUER_OWNER });
    const verifier = new RegistryClient(url);
    const before = await owner.addIssuers([issuerKey(1), issuerKey(2)]);

    await owner.removeIssuer(issuerKey(1));
    expect(await verifier.isValidIssuerRoot(before)).toBe(true);

    await owner.expireIssuerRoots();
    expect(await verifier.isValidIssuerRoot(before)).toBe(false);
    expect(await verifier.isIssuer(issuerKey(1))).toBe(false);
  });

  it("requires the owner token for issuer writes", async () => {
    const anonymous = new RegistryClient(url);
    expect((await rejection(anonymous.addIssuers([issuerKey(1)]))).status).toBe(401);

    const wrong = new RegistryClient(url, { token: REVOCATION_OWNER });
    expect((await rejection(wrong.addIssuers([issuerKey(1)]))).status).toBe(403);
  });

  it("revokes through authorized revokers and serves non-membership proofs", async () => {
    const owner = new RegistryClient(url, { token: REVOCATION_OWNER });
    const { token } = await owner.setRevoker("issuer-a", true);
    expect(token).toBeTypeOf("string");

    const issuerA = new RegistryClient(url, { token });
    const emptyRoot = await new RegistryClient(url).getRevocationRoot();
    expect(emptyRoot).toBe(0n);

    // The empty registry syncs too.
    expect((await new RegistryClient(url).syncRevocationRegistry()).root).toBe(0n);

    const root = await issuerA.revoke([10n, 30n]);
    const holder = await new RegistryClient(url).syncRevocationRegistry();
    expect(holder.root).toBe(root);
    expect(holder.generateProof(20n).proofType).toBe(PROOF_TYPE.NON_MEMBERSHIP);
    expect(holder.generateProof(30n).proofType).toBe(PROOF_TYPE.MEMBERSHIP);

    const verifier = new RegistryClient(url);
    expect(await verifier.isValidRevocationRoot(root)).toBe(true);
    expect(await verifier.isValidRevocationRoot(0n)).toBe(true);
    now += 60;
    expect(await verifier.isValidRevocationRoot(0n)).toBe(false);

    expect(await verifier.getRevocationStatus(30n)).toEqual({ isRevoked: true, revokedBy: "issuer-a" });
  });

  it("enforces revoker ownership and token rotation", async () => {
    const owner = new RegistryClient(url, { token: REVOCATION_OWNER });
    const a = new RegistryClient(url, { token: (await owner.setRevoker("issuer-a", true)).token });
    const b = new RegistryClient(url, { token: (await owner.setRevoker("issuer-b", true)).token });

    await a.revoke(5n);
    expect((await rejection(b.unrevoke(5n))).status).toBe(403);

    // The owner is not a revoker unless it authorizes itself.
    expect((await rejection(owner.revoke(6n))).status).toBe(401);

    // Re-authorizing rotates the token.
    const rotated = new RegistryClient(url, { token: (await owner.setRevoker("issuer-a", true)).token });
    expect((await rejection(a.revoke(7n))).status).toBe(401);
    await rotated.unrevoke(5n);

    await owner.setRevoker("issuer-b", false);
    expect((await rejection(b.revoke(8n))).status).toBe(403);
    expect(await owner.isRevoker("issuer-b")).toBe(false);
    expect(await owner.isRevoker("issuer-a")).toBe(true);
    // Revoker ids are not public.
    expect((await rejection(new RegistryClient(url).isRevoker("issuer-a"))).status).toBe(401);
  });

  it("validates input", async () => {
    const owner = new RegistryClient(url, { token: ISSUER_OWNER });
    const response = await fetch(`${url}/issuer/commitments`, {
      method: "POST",
      headers: { Authorization: `Bearer ${ISSUER_OWNER}`, "Content-Type": "application/json" },
      body: JSON.stringify({ commitments: ["-1"] }),
    });
    expect(response.status).toBe(400);
    expect((await rejection(owner.addIssuers([]))).status).toBe(400);
    expect((await fetch(`${url}/issuer/roots/xyz`)).status).toBe(400);
    expect((await fetch(`${url}/nope`)).status).toBe(404);
    expect((await fetch(`${url}/issuer/root`, { method: "DELETE" })).status).toBe(405);
  });

  it("persists both registries across restarts", async () => {
    const issuerOwner = new RegistryClient(url, { token: ISSUER_OWNER });
    const revocationOwner = new RegistryClient(url, { token: REVOCATION_OWNER });
    const issuerRoot = await issuerOwner.addIssuers([issuerKey(1), issuerKey(2)]);
    const { token } = await revocationOwner.setRevoker("issuer-a", true);
    const revocationRoot = await new RegistryClient(url, { token }).revoke([4n, 2n]);

    await registry.close();
    await start();

    expect(await new RegistryClient(url).getIssuerRoot()).toBe(issuerRoot);
    expect(await new RegistryClient(url).getRevocationRoot()).toBe(revocationRoot);
    // The revoker token survives the restart.
    await new RegistryClient(url, { token }).unrevoke(4n);
    expect(await new RegistryClient(url).isValidRevocationRoot(revocationRoot)).toBe(true);
  });

  it("does not expose a write that failed to persist", async () => {
    await registry.close();
    let failing = false;
    const store: StateStore<IssuerAuthorityState> = {
      load: async () => undefined,
      save: async () => {
        if (failing) throw new Error("disk full");
      },
    };
    registry = await createRegistryServer({ issuer: { ownerToken: ISSUER_OWNER, store }, clock: () => now });
    url = await registry.listen(0);

    const owner = new RegistryClient(url, { token: ISSUER_OWNER });
    const root = await owner.addIssuers([issuerKey(1)]);
    failing = true;
    expect((await rejection(owner.addIssuers([issuerKey(2)]))).status).toBe(503);
    expect(await new RegistryClient(url).getIssuerRoot()).toBe(root);
  });

  it("serializes concurrent writes", async () => {
    const owner = new RegistryClient(url, { token: ISSUER_OWNER });
    const commitments = Array.from({ length: 20 }, (_, i) => issuerKey(i + 1));
    await Promise.all(commitments.map((c) => owner.addIssuers([c])));

    const mirror = await new RegistryClient(url).syncIssuerRegistry();
    expect(mirror.size).toBe(20);
    expect(new Set(mirror.leaves)).toEqual(new Set(commitments));
  });
});
