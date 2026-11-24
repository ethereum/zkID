import type { IssuerRegistry } from "@coordination-network/issuer-registry";
import type { RevocationRegistry } from "@coordination-network/revocation-registry";

const WORD = 32;
const INDEX = 4;

export interface LeafRecord {
  value: bigint;
  nextValue: bigint;
}

/** Leaves a mirroring wallet must rewrite: new ones, and ones whose next pointer moved. */
export function changedLeafCount(before: LeafRecord[], after: LeafRecord[]): number {
  const old = new Map(before.map((l) => [l.value, l.nextValue]));
  return after.filter((l) => old.get(l.value) !== l.nextValue).length;
}

/** Bytes a mirroring wallet downloads: each changed leaf record (value, nextValue) plus the new root. */
export function mirrorUpdateBytes(changedLeaves: number): number {
  return changedLeaves * 2 * WORD + WORD;
}

/** Bytes a wallet that fetches proofs downloads: siblings, the leaf, its index and the root. */
export function proofFetchBytes(registry: "issuer" | "revocation", depth: number): number {
  const leaf = registry === "revocation" ? 2 * WORD : WORD;
  return depth * WORD + leaf + INDEX + WORD;
}

/** The least a mirror needs per update: one 32-byte value, plus the new root. */
export function mirrorMinBytes(updates: number): number {
  return updates * WORD + WORD;
}

/** Upper bound for an issuer mirror: each changed leaf is one 32-byte commitment, plus the new root. */
export function issuerMirrorBytes(changedLeaves: number): number {
  return changedLeaves * WORD + WORD;
}

/** The registry server's default `rootDuration` and its issuer depth cap, as served in GET bodies. */
const SERVER_ROOT_DURATION = 3600;
const SERVER_ISSUER_MAX_DEPTH = 8;

/** The body of GET /issuer. */
export function issuerSyncBody(reg: IssuerRegistry) {
  return { root: reg.root, depth: reg.depth, size: reg.size, maxDepth: SERVER_ISSUER_MAX_DEPTH, rootDuration: SERVER_ROOT_DURATION, leaves: reg.leaves };
}

/** The body of GET /revocation. */
export function revocationSyncBody(reg: RevocationRegistry) {
  const leaves = reg.leafSlots.map(({ value, nextValue }) => ({ value, nextValue }));
  return { root: reg.root, depth: reg.depth, size: reg.size, rootDuration: SERVER_ROOT_DURATION, leaves };
}

/** Bytes on the wire: the server's JSON, with bigints as decimal strings. */
export function serverJsonBytes(body: unknown): number {
  return Buffer.byteLength(JSON.stringify(body, (_k, v) => (typeof v === "bigint" ? v.toString() : v)));
}
