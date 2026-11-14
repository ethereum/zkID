// Thin wrapper around the `build_split_inputs` wasm export.
//
// Delegates to the shared `zkid-input-builder` Rust crate so the browser
// produces byte-identical JSON to `ecdsa-spartan2`'s `generate_split_inputs`.
// Parity is pinned by `spartan2-wasm/tests/input_builder_drift.rs` — the
// check that prevents `__placeholder__` witness failures from returning
// through input-builder drift.

import init, { build_split_inputs } from "./wasm/spartan2_wasm.js";
import type { CardContext } from "./pipeline";
import type { SmtCircuitInputs } from "./smt-client";

let wasmInit: Promise<unknown> | null = null;

/** Idempotent wasm-bindgen init shared across callers on the main thread. */
export async function ensureWasm(): Promise<void> {
  if (!wasmInit) wasmInit = init();
  await wasmInit;
}

export interface BuildInputsParams {
  card: CardContext;
  /** Raw PKCS#1 v1.5 signature from HiPKI, base64-encoded. */
  userSignatureB64: string;
  /** 31-byte UTF-8 `app_id` from the verifier — the bytes the card signed
   *  and the user-sig circuit consumes as `app_id_bytes`. */
  appIdBytes: Uint8Array;
  smtInputs: SmtCircuitInputs | null;
  /** Verifier-issued per-session field element (decimal string), bound into
   *  the user-sig proof via a Semaphore-style dummy square. */
  challenge: string;
}

export interface SplitInputs {
  certJson: string;
  userSigJson: string;
}

/**
 * Returns stringified JSON (not objects) because the circom witness calculator
 * accepts a JSON string; serialising once here avoids a round trip through
 * `JSON.stringify` in the Worker, and lets us `postMessage` without
 * structured-cloning a many-KB object tree.
 */
/**
 * The current time as the decimal integer `YYMMDDHHMMSS` (UTC). The cert-chain
 * proof checks the certificate's validity period against it, and the verifier
 * checks it against its own clock.
 */
export function currentTimeUtc(now: Date = new Date()): string {
  const year = now.getUTCFullYear();
  if (year < 2000 || year > 2049) {
    throw new Error(`year ${year} is outside the UTCTime range 2000..2049`);
  }
  const two = (n: number) => String(n).padStart(2, "0");
  return (
    two(year - 2000) +
    two(now.getUTCMonth() + 1) +
    two(now.getUTCDate()) +
    two(now.getUTCHours()) +
    two(now.getUTCMinutes()) +
    two(now.getUTCSeconds())
  );
}

export async function buildInputs(
  params: BuildInputsParams,
): Promise<SplitInputs> {
  await ensureWasm();
  const { card, userSignatureB64, appIdBytes, smtInputs, challenge } = params;
  const out = build_split_inputs(
    card.userCertDer,
    card.issuerCertDer,
    userSignatureB64,
    appIdBytes,
    card.serialHex,
    smtInputs,
    card.kIssuer,
    17,
    challenge,
    currentTimeUtc(),
  ) as { cert_chain: unknown; user_sig: unknown };
  return {
    certJson: JSON.stringify(out.cert_chain),
    userSigJson: JSON.stringify(out.user_sig),
  };
}
