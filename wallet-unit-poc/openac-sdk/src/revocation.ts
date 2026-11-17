// Credential revocation: LeanIMT+ (SHA-256) non-membership of C = sha256(r),
// where r is the holder's 32-byte revocation secret and C is signed into the
// credential as the `revocation_commitment` claim.

import { sha256 } from "@noble/hashes/sha2";
import {
  PROOF_TYPE,
  RevocationRegistry,
  SHA256_VALUE_BOUND,
  sha256Scheme,
  type RevocationProof,
} from "@coordination-network/revocation-registry";

import { InputError } from "./errors.js";
import { base64Decode, bigintToBase64url, bytesToBigInt } from "./utils.js";

/** Max tree depth compiled into the Show circuit (`revocationMaxDepth`). */
export const REVOCATION_MAX_DEPTH = 10;

/** JWT payload claim carrying the base64url-encoded 32-byte commitment. */
export const REVOCATION_COMMITMENT_CLAIM = "revocation_commitment";

export const REVOCATION_SECRET_BYTES = 32;

const LIMB_BITS = 128n;
const LIMB_MASK = (1n << LIMB_BITS) - 1n;

/** The registry the holder proves against: `RevocationRegistry` with `sha256Scheme`. */
export interface RevocationRegistryLike {
  readonly root: bigint;
  readonly scheme?: { readonly bound: bigint };
  generateProof(commitment: bigint): RevocationProof;
}

/** Holder-side revocation input to `present()`. */
export interface RevocationRequest {
  /** The 32-byte secret r whose sha256 is the credential's commitment (bytes or hex). */
  secret: Uint8Array | string;
  /** The revocation registry, synced with and checked against the published root. */
  registry: RevocationRegistryLike;
}

/**
 * Verifier-side check of the revocation root a proof was built against. Check it
 * against the registry of `issuerKey`, the issuer the proof was built under, or a
 * credential revoked by one issuer could be shown against another's registry.
 */
export type RevocationRootCheck = (
  root: bigint,
  issuerKey: import("./types.js").ProvenIssuerKey,
) => boolean | Promise<boolean>;

/** The Show circuit's revocation inputs; 256-bit values are [hi, lo] limbs. */
export interface RevocationWitness {
  revocationCommitment: bigint[];
  revocationSecret: bigint[];
  revocationLeafValue: bigint[];
  revocationLeafNextValue: bigint[];
  revocationLeafIndex: bigint;
  revocationDepth: bigint;
  revocationSiblings: bigint[][];
}

export function generateRevocationSecret(): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(REVOCATION_SECRET_BYTES));
}

export function computeRevocationCommitment(secret: Uint8Array | string): bigint {
  return bytesToBigInt(sha256(secretBytes(secret)));
}

/** Encodes a commitment for the `revocation_commitment` claim. */
export function encodeRevocationCommitment(commitment: bigint): string {
  if (commitment <= 0n || commitment >= SHA256_VALUE_BOUND) {
    throw new InputError("INVALID_ENCODING", "A revocation commitment must be in (0, 2^256)");
  }
  return bigintToBase64url(commitment);
}

export function decodeRevocationCommitment(encoded: string): bigint {
  if (!/^[A-Za-z0-9_-]{43}$/.test(encoded)) {
    throw new InputError(
      "INVALID_ENCODING",
      `${REVOCATION_COMMITMENT_CLAIM} must be 32 bytes as 43 base64url characters`,
    );
  }
  return bytesToBigInt(base64Decode(encoded));
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

/** Accepts exactly the given roots, for a verifier that trusts a single issuer. */
export function acceptRevocationRoots(roots: bigint[]): RevocationRootCheck {
  const accepted = new Set(roots);
  return (root) => accepted.has(root);
}

export function toLimbs(value: bigint): bigint[] {
  return [value >> LIMB_BITS, value & LIMB_MASK];
}

export function fromLimbs(hi: bigint, lo: bigint): bigint {
  return (hi << LIMB_BITS) | lo;
}

/**
 * Builds the Show circuit's revocation inputs. Throws `CREDENTIAL_REVOKED` when
 * the commitment is in the registry. An empty registry proves against root 0.
 */
export function buildRevocationWitness(
  secret: Uint8Array | string,
  commitment: bigint,
  registry: RevocationRegistryLike,
  maxDepth = REVOCATION_MAX_DEPTH,
): RevocationWitness {
  if (computeRevocationCommitment(secret) !== commitment) {
    throw new InputError(
      "INVALID_REVOCATION_SECRET",
      "sha256(revocation secret) does not match the credential's revocation commitment",
    );
  }
  if (registry.scheme && registry.scheme.bound !== SHA256_VALUE_BOUND) {
    throw new InputError("INVALID_REVOCATION_REGISTRY", "The revocation registry must use sha256Scheme");
  }

  const zero = (): bigint[] => [0n, 0n];
  const witness: RevocationWitness = {
    revocationCommitment: toLimbs(commitment),
    revocationSecret: toLimbs(bytesToBigInt(secretBytes(secret))),
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

function secretBytes(secret: Uint8Array | string): Uint8Array {
  const bytes = typeof secret === "string" ? hexToBytes(secret) : secret;
  if (bytes.length !== REVOCATION_SECRET_BYTES) {
    throw new InputError(
      "INVALID_REVOCATION_SECRET",
      `The revocation secret must be ${REVOCATION_SECRET_BYTES} bytes`,
    );
  }
  return bytes;
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (!/^([0-9a-fA-F]{2})*$/.test(clean)) {
    throw new InputError("INVALID_REVOCATION_SECRET", "The revocation secret is not valid hex");
  }
  return Uint8Array.from(clean.match(/../g) ?? [], (b) => parseInt(b, 16));
}
