import { randomBytes } from "crypto";
import { sha256 } from "@noble/hashes/sha2";
import { PROOF_TYPE, RevocationRegistry, sha256Scheme } from "@coordination-network/revocation-registry";
import { be32, bigintToBase64url, bufferToBigInt } from "./utils.ts";

export const REVOCATION_VALUE_ANCHOR = '"revocation_value":"';

const LIMB_MASK = (1n << 128n) - 1n;

/** An issuer's P-256 public key. */
export interface IssuerKeyPoint {
  x: bigint;
  y: bigint;
}

/** Show circuit revocation inputs; `revocationValue` is the signed revocation value. */
export interface RevocationWitness {
  issuerKeyX: bigint;
  issuerKeyY: bigint;
  revocationValue: bigint[];
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

/** A random non-zero 32-byte revocation value for the `revocation_value` claim. */
export function generateRevocationValue(): bigint {
  for (;;) {
    const value = bytesToBigInt(randomBytes(32));
    if (value !== 0n) return value;
  }
}

/** Domain tag hashed last into a revocation commitment. */
export const REVOCATION_COMMITMENT_TAG = 3n;

/** The revocation tree commitment sha256(be32(x) || be32(y) || be32(value) || be32(3)), as RevocationCommitment derives it. */
export function computeRevocationCommitment(issuer: IssuerKeyPoint, value: bigint): bigint {
  return bytesToBigInt(
    sha256(Buffer.concat([be32(issuer.x), be32(issuer.y), be32(value), be32(REVOCATION_COMMITMENT_TAG)])),
  );
}

/** be32(x) || be32(y) as big-endian bits, the `issuerKeyBits` Show passes to RevocationCheck. */
export function issuerKeyBits(issuer: IssuerKeyPoint): number[] {
  const bits = (v: bigint) => [...be32(v)].flatMap((byte) => byte.toString(2).padStart(8, "0").split("").map(Number));
  return [...bits(issuer.x), ...bits(issuer.y)];
}

export const encodeRevocationValue = bigintToBase64url;

export function createRevocationRegistry(commitments: bigint[] = []): RevocationRegistry {
  return new RevocationRegistry(commitments, sha256Scheme);
}

/** Show circuit revocation inputs for `value` under `issuer` against `registry` (empty registry: root 0). */
export function buildRevocationWitness(
  issuer: IssuerKeyPoint,
  value: bigint,
  registry: RevocationRegistry,
  maxDepth: number,
): RevocationWitness {
  const commitment = computeRevocationCommitment(issuer, value);
  const zero = () => [0n, 0n];
  const witness: RevocationWitness = {
    issuerKeyX: issuer.x,
    issuerKeyY: issuer.y,
    revocationValue: toLimbs(value),
    revocationLeafValue: zero(),
    revocationLeafNextValue: zero(),
    revocationLeafIndex: 0n,
    revocationDepth: 0n,
    revocationSiblings: Array.from({ length: maxDepth }, zero),
  };

  if (registry.root === 0n) return witness;

  const proof = registry.generateProof(commitment);
  if (proof.proofType !== PROOF_TYPE.NON_MEMBERSHIP) throw new Error("credential is revoked");
  if (proof.siblings.length > maxDepth) throw new Error("revocation tree is deeper than maxDepth");

  witness.revocationLeafValue = toLimbs(proof.leaf.value);
  witness.revocationLeafNextValue = toLimbs(proof.leaf.nextValue);
  witness.revocationLeafIndex = BigInt(proof.leafIndex);
  witness.revocationDepth = BigInt(proof.siblings.length);
  proof.siblings.forEach((sibling, i) => (witness.revocationSiblings[i] = toLimbs(sibling)));
  return witness;
}
