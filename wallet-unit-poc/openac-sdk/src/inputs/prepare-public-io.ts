// Reading the JWT (Prepare) proof's public IO.
//
// Circom lays public IO out as `[outputs..., public inputs...]`, so for the JWT
// main components (see circom/circuits/main/jwt*.circom):
//
//   [0 .. n)          decodeFlags[n]             (public inputs; no outputs)
//   [n .. 2n)         claimFormats[n]
//
// The circuit has no public outputs: normalizedClaimValues would hand the
// verifier the exact claim, KeyBindingX/Y would link every presentation and
// pubKeyX/Y would reveal the issuer. All reach Show privately through
// `comm_W_shared` instead (issuer hiding: Show outputs only the registry root).
//
// where `n = maxMatches - 2`. Total length is `2n`.
//
// Verified against `circom/build/jwt_1k/jwt_1k.sym` (n = 2, length 4); the Rust
// tests in `ecdsa-spartan2/src/utils.rs` assert the same layout against the
// compiled circuits.

import { VerificationError } from "../errors.js";
import type { ClaimNormalization } from "../types.js";

interface PreparePublicIoLayout {
  claimCount: number;
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
  const claimCount = publicValues.length / 2;
  if (!Number.isInteger(claimCount) || claimCount < 1) {
    throw new VerificationError(
      "INVALID_PROOF_FORMAT",
      `Proof exposes ${publicValues.length} public values, which is not a valid JWT circuit ` +
        `public IO size (expected 2n for n claim slots)`,
    );
  }
  // The vector length is attacker-controlled (spartan2's validate() never checks
  // it against S.num_public), so a forked prover can truncate to a different but
  // still well-formed length. Cross-check against the count the verifier expects.
  if (expectedClaimCount !== undefined && claimCount !== expectedClaimCount) {
    throw new VerificationError(
      "INVALID_PROOF_FORMAT",
      `Proof exposes ${claimCount} claim slots but the verifier expects ${expectedClaimCount}`,
    );
  }
  return {
    claimCount,
    decodeFlagsStart: 0,
    claimFormatsStart: claimCount,
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
