// Issuer hiding: the Show circuit proves the issuer's key is in a SHA-256
// LeanIMT (an `OpenACIssuerRegistry` on chain) and outputs only the root.

import {
  IssuerRegistry,
  sha256Hash2,
  sha256Scheme,
  type IssuerProof,
} from "@coordination-network/issuer-registry";

import { InputError, VerificationError } from "./errors.js";
import { issuerPublicKeyToPoint, type IssuerKeyPoint } from "./inputs/issuer-key.js";
import type { IssuerPublicKey } from "./types.js";

export { IssuerRegistry, sha256Scheme };
export type { IssuerProof };

/** Show `maxIssuerDepth`: a registry holds at most 2^8 issuers. */
export const ISSUER_TREE_MAX_DEPTH = 8;

const LIMB_BITS = 128n;
const LIMB_MASK = (1n << LIMB_BITS) - 1n;

/** The registry leaf of an issuer: `sha256(be32(x) || be32(y))`, as the circuit derives it. */
export function issuerCommitment(key: IssuerPublicKey | IssuerKeyPoint): bigint {
  const { x, y } = "x" in key && typeof key.x === "bigint"
    ? (key as IssuerKeyPoint)
    : issuerPublicKeyToPoint(key as IssuerPublicKey);
  return sha256Hash2(x, y);
}

/** A SHA-256 issuer registry, as a mirror of the on-chain one or as the authority. */
export function createIssuerRegistry(
  issuers: Array<IssuerPublicKey | bigint> = [],
): IssuerRegistry {
  const commitments = issuers.map((i) => (typeof i === "bigint" ? i : issuerCommitment(i)));
  return new IssuerRegistry(commitments, sha256Scheme);
}

export function toLimbs(value: bigint): [bigint, bigint] {
  return [value >> LIMB_BITS, value & LIMB_MASK];
}

export function fromLimbs(hi: bigint, lo: bigint): bigint {
  if (hi < 0n || lo < 0n || hi > LIMB_MASK || lo > LIMB_MASK) {
    throw new VerificationError("INVALID_PROOF_FORMAT", "Issuer root limb is not 128 bits");
  }
  return (hi << LIMB_BITS) | lo;
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
