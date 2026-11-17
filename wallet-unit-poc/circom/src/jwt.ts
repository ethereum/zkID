import { strict as assert } from "assert";
import { generateES256Inputs } from "./es256.ts";
import type { Es256CircuitParams, JwkEcdsaPublicKey, PemPublicKey } from "./es256.ts";
import { encodeClaims, stringToPaddedBigIntArray } from "./utils.ts";
import { REVOCATION_COMMITMENT_ANCHOR } from "./revocation.ts";

// The JWT Circuit Parameters
export interface JwtCircuitParams {
  es256: Es256CircuitParams;
  maxB64PayloadLength: number;
  maxMatches: number;
  maxSubstringLength: number;
  maxClaimLength: number;
}

// Generate JWT Circuit Parameters
export function generateJwtCircuitParams(params: number[]): JwtCircuitParams {
  return {
    es256: {
      maxMessageLength: params[0],
    },
    maxB64PayloadLength: params[1],
    maxMatches: params[2],
    maxSubstringLength: params[3],
    maxClaimLength: params[4],
  };
}

// Generate JWT circuit inputs
export function generateJwtInputs(
  params: JwtCircuitParams,
  token: string,
  pk: JwkEcdsaPublicKey | PemPublicKey,
  matches: string[],
  claims: string[],
  claimFormats: number[] = []
) {
  // we are not checking the JWT token format, assuming that is correct
  const [b64header, b64payload, b64signature] = token.split(".");

  // check that we are not exceeding the limits
  assert.ok(b64payload.length <= params.maxB64PayloadLength);
  const maxClaims = params.maxMatches - 2;
  assert.ok(maxClaims >= 0, "maxMatches must be at least 2");
  assert.ok(claims.length <= maxClaims);
  assert.ok(matches.length + 2 <= params.maxMatches);
  assert.ok(matches.length === claims.length, `matches.length (${matches.length}) must equal claims.length (${claims.length})`);

  // generate inputs for the ES256 validation
  let es256Inputs = generateES256Inputs(params.es256, `${b64header}.${b64payload}`, b64signature, pk);

  const payload = atob(b64payload);

  const patterns = ['"x":"', '"y":"', ...matches];

  assert.ok(patterns.length <= params.maxMatches);

  let matchSubstring: bigint[][] = [];
  let matchLength: number[] = [];
  let matchIndex: number[] = [];
  for (const pattern of patterns) {
    assert.ok(pattern.length <= params.maxSubstringLength);
    const index = payload.indexOf(pattern);
    assert.ok(index != -1);
    matchSubstring.push(stringToPaddedBigIntArray(pattern, params.maxSubstringLength));
    matchLength.push(pattern.length);
    matchIndex.push(index);
  }

  while (matchIndex.length < params.maxMatches) {
    matchSubstring.push(stringToPaddedBigIntArray("", params.maxSubstringLength));
    matchLength.push(0);
    matchIndex.push(0);
  }

  let { claimArray, claimLengths } = encodeClaims(claims, maxClaims, params.maxClaimLength);

  // Decode only claims the caller declared a format for. Decoding a claim
  // under a defaulted "uint" format normalizes non-numeric bytes into a
  // meaningless field element, which the normalizer now rejects outright.
  const decodeFlagsOut: number[] = [];
  for (let i = 0; i < maxClaims; i++) {
    decodeFlagsOut.push(i < claims.length && i < claimFormats.length ? 1 : 0);
  }

  const claimFormatsOut: bigint[] = [];
  for (let i = 0; i < maxClaims; i++) {
    claimFormatsOut.push(BigInt(i < claimFormats.length ? claimFormats[i] : 1));
  }

  const revocationCommitmentIndex = payload.indexOf(REVOCATION_COMMITMENT_ANCHOR);
  assert.ok(revocationCommitmentIndex !== -1, "payload has no revocation_commitment");

  return {
    ...es256Inputs,
    revocationCommitmentIndex,
    periodIndex: token.indexOf("."),
    matchesCount: patterns.length,
    matchSubstring,
    matchLength,
    matchIndex,
    claims: claimArray,
    claimLengths,
    decodeFlags: decodeFlagsOut,
    claimFormats: claimFormatsOut,
  };
}
