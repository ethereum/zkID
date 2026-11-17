import { p256 } from "@noble/curves/nist.js";
import { IssuerRegistry, sha256Hash2, sha256Scheme } from "@coordination-network/issuer-registry";
import { toLimbs } from "./utils.ts";

export { toLimbs };

/** Show `maxIssuerDepth` (circuits.json). */
export const ISSUER_TREE_MAX_DEPTH = 8;

export interface IssuerKeyPoint {
  x: bigint;
  y: bigint;
}

export type IssuerMembershipInputs = {
  issuerKeyX: bigint;
  issuerKeyY: bigint;
  issuerTreeDepth: bigint;
  issuerTreeIndex: bigint;
  issuerTreeSiblings: bigint[][];
};


/** Leaf of an issuer: sha256(be32(x) || be32(y)), as IssuerCommitment derives it. */
export const issuerCommitment = ({ x, y }: IssuerKeyPoint): bigint => sha256Hash2(x, y);

/** A SHA-256 issuer registry over the given keys. */
export function buildIssuerRegistry(issuers: IssuerKeyPoint[]): IssuerRegistry {
  return new IssuerRegistry(issuers.map(issuerCommitment), sha256Scheme);
}

/** Show inputs proving `issuer` is in `registry` (default: a registry of just `issuer`). */
export function generateIssuerMembershipInputs(
  issuer: IssuerKeyPoint,
  registry: IssuerRegistry = buildIssuerRegistry([issuer]),
  maxDepth = ISSUER_TREE_MAX_DEPTH
): IssuerMembershipInputs {
  const proof = registry.generateProof(issuerCommitment(issuer));
  const siblings = proof.siblings.map(toLimbs);
  while (siblings.length < maxDepth) siblings.push([0n, 0n]);
  return {
    issuerKeyX: issuer.x,
    issuerKeyY: issuer.y,
    issuerTreeDepth: BigInt(proof.siblings.length),
    issuerTreeIndex: BigInt(proof.index),
    issuerTreeSiblings: siblings,
  };
}

/** Stand-in issuer for Show-only tests: the P-256 generator. */
export const DEFAULT_TEST_ISSUER: IssuerKeyPoint = { x: p256.Point.BASE.x, y: p256.Point.BASE.y };
