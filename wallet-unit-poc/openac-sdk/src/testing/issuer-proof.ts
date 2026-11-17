import { createIssuerRegistry, issuerCommitment, type IssuerProof } from "../issuer-hiding.js";
import type { IssuerPublicKey } from "../types.js";

/** Membership proof of `issuer` in a registry of `[...others, issuer]`. */
export function issuerProofFor(
  issuer: IssuerPublicKey,
  others: IssuerPublicKey[] = [],
): IssuerProof {
  return createIssuerRegistry([...others, issuer]).generateProof(issuerCommitment(issuer));
}
