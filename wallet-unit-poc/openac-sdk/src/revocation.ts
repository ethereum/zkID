// Credential revocation: LeanIMT+ (SHA-256) non-membership of the commitment
// v = sha256(be32(x) || be32(y) || be32(r) || be32(3)), where (x, y) is the issuer key and r
// is the 32-byte revocation value the issuer signs into the credential as the
// `revocation_value` claim. The circuit derives v from the same issuer key and
// value the credential circuit verified, so a holder cannot swap in another commitment.
//
// One registry holds the revoked commitments of every issuer. A per-issuer registry
// would make the revocation root a proof outputs identify the issuer, which issuer
// hiding keeps private. The key in the commitment keeps equal values under different
// issuers apart.

import { sha256 } from "@noble/hashes/sha2";
import {
  PROOF_TYPE,
  RevocationRegistry,
  SHA256_VALUE_BOUND,
  sha256Scheme,
  type RevocationProof,
} from "@coordination-network/revocation-registry";

import { InputError } from "./errors.js";
import { toLimbs } from "./limbs.js";
import { toIssuerKeyPoint, type IssuerKeyPoint } from "./inputs/issuer-key.js";
import type { IssuerPublicKey } from "./types.js";
import { base64Decode, bigintToBase64url, bigintToBytes, bytesToBigInt } from "./utils.js";

/** Max tree depth compiled into the Show circuit (`revocationMaxDepth`). */
export const REVOCATION_MAX_DEPTH = 10;

/** JWT payload claim carrying the base64url-encoded 32-byte revocation value. */
export const REVOCATION_VALUE_CLAIM = "revocation_value";

export const REVOCATION_VALUE_BYTES = 32;

/** Domain tag hashed last into a revocation commitment (issuer commitments use 2). */
export const REVOCATION_COMMITMENT_TAG = 3n;

/** The registry the holder proves against: `RevocationRegistry` with `sha256Scheme`. */
export interface RevocationRegistryLike {
  readonly root: bigint;
  readonly scheme?: { readonly bound: bigint };
  generateProof(commitment: bigint): RevocationProof;
}

/** Holder-side revocation input to `present()`. */
export interface RevocationRequest {
  /** The revocation registry, synced with and checked against the published root. */
  registry: RevocationRegistryLike;
}

/**
 * Verifier-side check of the revocation root a proof was built against, e.g.
 * `OpenACRevocationRegistry.isValidRoot` on chain.
 */
export type RevocationRootCheck = (root: bigint) => boolean | Promise<boolean>;

/**
 * The Show circuit's revocation inputs; 256-bit values are [hi, lo] limbs.
 * `revocationValue` is the signed revocation value r, shared with Prepare.
 */
export interface RevocationWitness {
  revocationValue: bigint[];
  revocationLeafValue: bigint[];
  revocationLeafNextValue: bigint[];
  revocationLeafIndex: bigint;
  revocationDepth: bigint;
  revocationSiblings: bigint[][];
}

/**
 * Issuer side: a random non-zero 32-byte revocation value for a new credential.
 * It must be unpredictable, since anyone who knows it and the issuer key can
 * compute the credential's revocation commitment.
 */
export function generateRevocationValue(): bigint {
  for (;;) {
    const value = bytesToBigInt(globalThis.crypto.getRandomValues(new Uint8Array(REVOCATION_VALUE_BYTES)));
    if (value !== 0n) return value;
  }
}

/**
 * The revocation commitment of a credential: `sha256(be32(x) || be32(y) || be32(value) || be32(3))`
 * for issuer key (x, y) and the signed revocation value, as the Show circuit derives it.
 * The issuer inserts this to revoke the credential.
 */
export function computeRevocationCommitment(
  issuerKey: IssuerPublicKey | IssuerKeyPoint,
  value: bigint,
): bigint {
  assertRevocationValue(value);
  const { x, y } = toIssuerKeyPoint(issuerKey);
  const input = new Uint8Array(128);
  input.set(bigintToBytes(x, 32), 0);
  input.set(bigintToBytes(y, 32), 32);
  input.set(bigintToBytes(value, 32), 64);
  input.set(bigintToBytes(REVOCATION_COMMITMENT_TAG, 32), 96);
  return bytesToBigInt(sha256(input));
}

/**
 * Encodes a revocation value for the `revocation_value` claim. The claim holds r
 * itself, never its revocation commitment: the circuit hashes r into the commitment.
 */
export function encodeRevocationValue(value: bigint): string {
  assertRevocationValue(value);
  return bigintToBase64url(value);
}

export function decodeRevocationValue(encoded: string): bigint {
  if (!/^[A-Za-z0-9_-]{43}$/.test(encoded)) {
    throw new InputError(
      "INVALID_ENCODING",
      `${REVOCATION_VALUE_CLAIM} must be 32 bytes as 43 base64url characters`,
    );
  }
  const value = bytesToBigInt(base64Decode(encoded));
  assertRevocationValue(value);
  return value;
}

/** A SHA-256 revocation registry, matching `Sha256Revocation` on chain. */
export function createRevocationRegistry(commitments: bigint[] = []): RevocationRegistry {
  return new RevocationRegistry(commitments, sha256Scheme);
}

/** Rebuilds a registry from its physical slots, e.g. the contract's `getLeaf`. */
export function revocationRegistryFromLeaves(
  leaves: { value: bigint; nextValue: bigint }[],
): RevocationRegistry {
  return RevocationRegistry.fromLeaves(leaves, sha256Scheme);
}

/** Accepts exactly the given roots, e.g. the registry's current and recent roots. */
export function acceptRevocationRoots(roots: bigint[]): RevocationRootCheck {
  const accepted = new Set(roots);
  return (root) => accepted.has(root);
}

/**
 * Builds the Show circuit's revocation inputs for the credential with `value`
 * signed by `issuerKey`. Throws `CREDENTIAL_REVOKED` when its commitment is in the
 * registry. An empty registry proves against root 0.
 */
export function buildRevocationWitness(
  issuerKey: IssuerPublicKey | IssuerKeyPoint,
  value: bigint,
  registry: RevocationRegistryLike,
  maxDepth = REVOCATION_MAX_DEPTH,
): RevocationWitness {
  if (registry.scheme && registry.scheme.bound !== SHA256_VALUE_BOUND) {
    throw new InputError("INVALID_REVOCATION_REGISTRY", "The revocation registry must use sha256Scheme");
  }
  const commitment = computeRevocationCommitment(issuerKey, value);

  const zero = (): bigint[] => [0n, 0n];
  const witness: RevocationWitness = {
    revocationValue: toLimbs(value),
    revocationLeafValue: zero(),
    revocationLeafNextValue: zero(),
    revocationLeafIndex: 0n,
    revocationDepth: 0n,
    revocationSiblings: Array.from({ length: maxDepth }, zero),
  };

  if (registry.root === 0n) return witness;

  const proof = registry.generateProof(commitment);
  if (proof.proofType !== PROOF_TYPE.NON_MEMBERSHIP) {
    throw new InputError("CREDENTIAL_REVOKED", "The credential's revocation commitment is revoked");
  }
  if (proof.siblings.length > maxDepth) {
    throw new InputError(
      "PARAMS_EXCEEDED",
      `Revocation tree depth ${proof.siblings.length} exceeds the circuit's max depth ${maxDepth}`,
    );
  }

  witness.revocationLeafValue = toLimbs(proof.leaf.value);
  witness.revocationLeafNextValue = toLimbs(proof.leaf.nextValue);
  witness.revocationLeafIndex = BigInt(proof.leafIndex);
  witness.revocationDepth = BigInt(proof.siblings.length);
  proof.siblings.forEach((sibling, i) => {
    witness.revocationSiblings[i] = toLimbs(sibling);
  });
  return witness;
}

function assertRevocationValue(value: bigint): void {
  if (value <= 0n || value >= SHA256_VALUE_BOUND) {
    throw new InputError("INVALID_ENCODING", "A revocation value must be in (0, 2^256)");
  }
}
