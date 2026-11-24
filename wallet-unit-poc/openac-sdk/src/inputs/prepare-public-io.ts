// Reading the JWT (Prepare) proof's public IO.
//
// Circom lays public IO out as `[outputs..., public inputs...]`, so for the JWT
// main components (see circom/circuits/main/jwt*.circom):
//
//   [0]               pubKeyX                    (public inputs; no outputs)
//   [1]               pubKeyY
//   [2 .. n + 2)      decodeFlags[n]
//   [n + 2 .. 2n + 2) claimFormats[n]
//
// The circuit has no public outputs: normalizedClaimValues would hand the
// verifier the exact claim, and KeyBindingX/Y would be a stable identifier
// linking every presentation from the credential. Both reach Show privately
// through `comm_W_shared` instead.
//
// where `n = maxMatches - 2`. Total length is `2n + 2`, which determines `n`
// from the vector alone, so nothing has to thread the circuit size through.
//
// Verified against `circom/build/jwt_1k/jwt_1k.sym` (n = 2, length 6); the Rust
// tests in `ecdsa-spartan2/src/utils.rs` assert the same layout against the
// compiled circuits.

import { VerificationError } from "../errors.js";
import type { ClaimNormalization } from "../types.js";

export interface IssuerKeyPoint {
  x: bigint;
  y: bigint;
}

interface PreparePublicIoLayout {
  claimCount: number;
  issuerKeyXIndex: number;
  decodeFlagsStart: number;
  claimFormatsStart: number;
}

/**
 * Derive the public IO layout from the vector's length.
 *
 * Throws `VerificationError("INVALID_PROOF_FORMAT")` for a length no JWT
 * circuit can produce, which is the symptom of a proof from a different circuit
 * or a stale key.
 */
function layoutOf(
  publicValues: bigint[],
  expectedClaimCount?: number,
): PreparePublicIoLayout {
  const claimCount = (publicValues.length - 2) / 2;
  if (!Number.isInteger(claimCount) || claimCount < 1) {
    throw new VerificationError(
      "INVALID_PROOF_FORMAT",
      `Proof exposes ${publicValues.length} public values, which is not a valid JWT circuit ` +
        `public IO size (expected 2n + 2 for n claim slots)`,
    );
  }
  // spartan2's validate() requires the length to equal the verifying key's num_public,
  // so this cross-checks that key against the claim count the verifier expects.
  if (expectedClaimCount !== undefined && claimCount !== expectedClaimCount) {
    throw new VerificationError(
      "INVALID_PROOF_FORMAT",
      `Proof exposes ${claimCount} claim slots but the verifier expects ${expectedClaimCount}`,
    );
  }
  return {
    claimCount,
    issuerKeyXIndex: 0,
    decodeFlagsStart: 2,
    claimFormatsStart: claimCount + 2,
  };
}

/**
 * Extract (pubKeyX, pubKeyY), the issuer key the circuit's ES256 check ran
 * against, from a credential proof's public values.
 */
export function extractIssuerKeyFromPreparePublicValues(
  publicValues: bigint[],
  expectedClaimCount?: number,
): IssuerKeyPoint {
  const { issuerKeyXIndex } = layoutOf(publicValues, expectedClaimCount);
  return {
    x: publicValues[issuerKeyXIndex]!,
    y: publicValues[issuerKeyXIndex + 1]!,
  };
}

/**
 * Extract the per-claim decode flags and format codes the circuit normalized
 * `normalizedClaimValues` under.
 *
 * A verifier needs these to know what the claim values a predicate compared
 * against actually mean. See `checkNormalizationSupports`.
 */
export function extractClaimNormalizationFromPreparePublicValues(
  publicValues: bigint[],
  expectedClaimCount?: number,
): ClaimNormalization {
  const { claimCount, decodeFlagsStart, claimFormatsStart } = layoutOf(
    publicValues,
    expectedClaimCount,
  );
  const slice = (start: number) =>
    publicValues.slice(start, start + claimCount).map((v) => Number(v));

  return {
    decodeFlags: slice(decodeFlagsStart),
    claimFormats: slice(claimFormatsStart),
  };
}
