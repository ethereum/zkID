import { InputError } from "./errors.js";
import type { JwtCircuitParams } from "./types.js";

export type VcSize = "1k" | "2k" | "4k" | "8k";

export const JWT_PARAMS_BY_SIZE: Record<VcSize, JwtCircuitParams> = {
  "1k": {
    maxMessageLength: 1280,
    maxB64PayloadLength: 960,
    maxMatches: 4,
    maxSubstringLength: 50,
    maxClaimLength: 128,
  },
  "2k": {
    maxMessageLength: 2048,
    maxB64PayloadLength: 2000,
    maxMatches: 4,
    maxSubstringLength: 50,
    maxClaimLength: 128,
  },
  "4k": {
    maxMessageLength: 4096,
    maxB64PayloadLength: 4000,
    maxMatches: 4,
    maxSubstringLength: 50,
    maxClaimLength: 128,
  },
  "8k": {
    maxMessageLength: 8192,
    maxB64PayloadLength: 8000,
    maxMatches: 4,
    maxSubstringLength: 50,
    maxClaimLength: 128,
  },
};

export const VC_SIZES: readonly VcSize[] = ["1k", "2k", "4k", "8k"] as const;

/**
 * Witness index of `main.normalizedClaimValues[0]` in each compiled JWT circuit.
 *
 * The JWT circuit publishes nothing. Claim values would reveal the exact
 * attribute; the device key (KeyBindingX/Y, immediately after these) would be a
 * constant identifier linking every presentation. Both are private signals, so
 * their offsets shift with `maxMessageLength` — hence the per-size table.
 *
 * Mirrors `CircuitSize::claim_values_witness_start` in ecdsa-spartan2. Both are
 * re-derived from the circuits' `.sym` files by their respective layout tests,
 * so a recompile that moves these fails loudly.
 */
export const CLAIM_VALUES_WITNESS_START: Record<VcSize, number> = {
  "1k": 2463,
  "2k": 4011,
  "4k": 7559,
  "8k": 14655,
};

/**
 * Witness index of `main.claimIdentifierHashes[0]` in each compiled JWT circuit.
 * Immediately follows normalizedClaimValues[maxClaims]. Read alongside the claim
 * values and carried to Show via comm_W_shared to bind slots to attribute names.
 */
export const CLAIM_IDENTITY_WITNESS_START: Record<VcSize, number> = {
  "1k": 2527,
  "2k": 4075,
  "4k": 7623,
  "8k": 14719,
};

export function selectVcSizeForSigningInput(byteLength: number): VcSize {
  for (const size of VC_SIZES) {
    if (byteLength <= JWT_PARAMS_BY_SIZE[size].maxMessageLength) return size;
  }
  throw new InputError(
    "PARAMS_EXCEEDED",
    `Signing input ${byteLength}B exceeds largest circuit (8k = 8192B). Use a smaller credential.`,
  );
}
