import { sha256 } from "@noble/hashes/sha2";
import { PROOF_TYPE, RevocationRegistry, sha256Scheme } from "@coordination-network/revocation-registry";
import { bigintToBase64url, bufferToBigInt } from "./utils.ts";

export const REVOCATION_COMMITMENT_ANCHOR = '"revocation_commitment":"';

const LIMB_MASK = (1n << 128n) - 1n;

export interface RevocationWitness {
  revocationCommitment: bigint[];
  revocationSecret: bigint[];
  revocationLeafValue: bigint[];
  revocationLeafNextValue: bigint[];
  revocationLeafIndex: bigint;
  revocationDepth: bigint;
  revocationSiblings: bigint[][];
}

export function toLimbs(value: bigint): bigint[] {
  return [value >> 128n, value & LIMB_MASK];
}

export function bytesToBigInt(bytes: Uint8Array): bigint {
  return bufferToBigInt(Buffer.from(bytes));
}

export function computeRevocationCommitment(secret: Uint8Array): bigint {
  return bytesToBigInt(sha256(secret));
}

export const encodeRevocationCommitment = bigintToBase64url;

export function createRevocationRegistry(commitments: bigint[] = []): RevocationRegistry {
  return new RevocationRegistry(commitments, sha256Scheme);
}

/** Show circuit revocation inputs for `secret` against `registry` (empty registry: root 0). */
export function buildRevocationWitness(
  secret: Uint8Array,
  registry: RevocationRegistry,
  maxDepth: number,
): RevocationWitness {
  const commitment = computeRevocationCommitment(secret);
  const zero = () => [0n, 0n];
  const witness: RevocationWitness = {
    revocationCommitment: toLimbs(commitment),
    revocationSecret: toLimbs(bytesToBigInt(secret)),
    revocationLeafValue: zero(),
    revocationLeafNextValue: zero(),
    revocationLeafIndex: 0n,
    revocationDepth: 0n,
    revocationSiblings: Array.from({ length: maxDepth }, zero),
  };

  if (registry.root === 0n) return witness;

  const proof = registry.generateProof(commitment);
  if (proof.proofType !== PROOF_TYPE.NON_MEMBERSHIP) throw new Error("commitment is revoked");
  if (proof.siblings.length > maxDepth) throw new Error("revocation tree is deeper than maxDepth");

  witness.revocationLeafValue = toLimbs(proof.leaf.value);
  witness.revocationLeafNextValue = toLimbs(proof.leaf.nextValue);
  witness.revocationLeafIndex = BigInt(proof.leafIndex);
  witness.revocationDepth = BigInt(proof.siblings.length);
  proof.siblings.forEach((sibling, i) => (witness.revocationSiblings[i] = toLimbs(sibling)));
  return witness;
}
