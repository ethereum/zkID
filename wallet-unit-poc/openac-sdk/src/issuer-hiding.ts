// Issuer hiding: the Show circuit proves the issuer's key is in a SHA-256
// LeanIMT (an `OpenACIssuerRegistry` on chain) and outputs only the root.

import { sha256 } from "@noble/hashes/sha2";
import {
  IssuerRegistry,
  sha256Scheme,
  type IssuerProof,
} from "@coordination-network/issuer-registry";

import { InputError } from "./errors.js";
import { toLimbs, fromLimbs } from "./limbs.js";
import { toIssuerKeyPoint, type IssuerKeyPoint } from "./inputs/issuer-key.js";
import type { IssuerPublicKey } from "./types.js";
import { bigintToBytes, bytesToBigInt } from "./utils.js";

export { IssuerRegistry, sha256Scheme as issuerSha256Scheme };
export { toLimbs, fromLimbs };
export type { IssuerProof };

/** Show `maxIssuerDepth`: a registry holds at most 2^8 issuers. */
export const ISSUER_TREE_MAX_DEPTH = 8;

/** Domain tag hashed last into an issuer commitment (revocation entries use 3). */
export const ISSUER_COMMITMENT_TAG = 2n;

/**
 * The registry leaf of an issuer: `sha256(be32(x) || be32(y) || be32(2))`, as the
 * circuit derives it. The tag keeps it from matching an internal node, sha256(left || right).
 */
export function issuerCommitment(key: IssuerPublicKey | IssuerKeyPoint): bigint {
  const { x, y } = toIssuerKeyPoint(key);
  const input = new Uint8Array(96);
  input.set(bigintToBytes(x, 32), 0);
  input.set(bigintToBytes(y, 32), 32);
  input.set(bigintToBytes(ISSUER_COMMITMENT_TAG, 32), 64);
  return bytesToBigInt(sha256(input));
}

/** A SHA-256 issuer registry, as a mirror of the on-chain one or as the authority. */
export function createIssuerRegistry(
  issuers: Array<IssuerPublicKey | bigint> = [],
): IssuerRegistry {
  const commitments = issuers.map((i) => (typeof i === "bigint" ? i : issuerCommitment(i)));
  return new IssuerRegistry(commitments, sha256Scheme);
}

/**
 * Verifier-side check of the issuer registry root a proof was built against,
 * e.g. `OpenACIssuerRegistry.isValidRoot` on chain.
 */
export type IssuerRootCheck = (issuerRoot: bigint) => boolean | Promise<boolean>;

/** Accepts exactly the given issuer registry roots, e.g. the registry's current and recent roots. */
export function acceptIssuerRoots(roots: bigint[]): IssuerRootCheck {
  const accepted = new Set(roots);
  return (root) => accepted.has(root);
}

export interface IssuerMembershipInputs {
  issuerKeyX: bigint;
  issuerKeyY: bigint;
  issuerTreeDepth: bigint;
  issuerTreeIndex: bigint;
  issuerTreeSiblings: bigint[][];
}

/** Show circuit inputs proving `issuerKey` is the leaf of `proof`. */
export function buildIssuerMembershipInputs(
  issuerKey: IssuerKeyPoint,
  proof: IssuerProof,
  maxDepth = ISSUER_TREE_MAX_DEPTH,
): IssuerMembershipInputs {
  if (proof.leaf !== issuerCommitment(issuerKey)) {
    throw new InputError("INVALID_ISSUER_PROOF", "Issuer proof is not for the credential's issuer");
  }
  if (proof.siblings.length > maxDepth) {
    throw new InputError(
      "PARAMS_EXCEEDED",
      `Issuer tree depth ${proof.siblings.length} exceeds ${maxDepth}`,
    );
  }
  if (!IssuerRegistry.verifyProof(proof, sha256Scheme)) {
    throw new InputError("INVALID_ISSUER_PROOF", "Issuer proof does not verify");
  }

  // LeanIMT proofs omit promoted levels, so depth is the sibling count.
  const siblings = proof.siblings.map(toLimbs);
  while (siblings.length < maxDepth) siblings.push([0n, 0n]);

  return {
    issuerKeyX: issuerKey.x,
    issuerKeyY: issuerKey.y,
    issuerTreeDepth: BigInt(proof.siblings.length),
    issuerTreeIndex: BigInt(proof.index),
    issuerTreeSiblings: siblings,
  };
}
