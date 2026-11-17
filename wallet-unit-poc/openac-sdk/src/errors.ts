export type ErrorCode =
  | "SETUP_FAILED"
  | "SETUP_NOT_SUPPORTED"
  | "KEYS_NOT_FOUND"
  | "KEY_LOAD_FAILED"
  | "KEY_INTEGRITY_FAILED"
  | "PROOF_GENERATION_FAILED"
  | "WITNESS_GENERATION_FAILED"
  | "REBLIND_FAILED"
  | "VERIFICATION_FAILED"
  | "INVALID_PROOF_FORMAT"
  | "COMMITMENT_MISMATCH"
  | "INVALID_JWT"
  | "AMBIGUOUS_PAYLOAD"
  | "INVALID_KEY"
  | "INVALID_SIGNATURE"
  | "MISSING_DISCLOSURE"
  | "BIRTHDAY_NOT_FOUND"
  | "CLAIM_NOT_FOUND"
  | "CLAIM_FORMAT_MISMATCH"
  | "PARAMS_EXCEEDED"
  | "INVALID_NONCE"
  | "INVALID_ENCODING"
  | "INVALID_REVOCATION_SECRET"
  | "INVALID_REVOCATION_REGISTRY"
  | "MISSING_REVOCATION_INPUTS"
  | "CREDENTIAL_REVOKED"
  | "WASM_LOAD_FAILED"
  | "WASM_OOM"
  | "WASM_NOT_INITIALIZED";

export class OpenACError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message: string, cause?: unknown) {
    super(message);
    this.name = "OpenACError";
    this.code = code;
    if (cause) this.cause = cause;
  }
}

export class SetupError extends OpenACError {
  constructor(code: "SETUP_FAILED" | "KEYS_NOT_FOUND", message: string, cause?: unknown) {
    super(code, message, cause);
    this.name = "SetupError";
  }
}

export class ProofError extends OpenACError {
  constructor(
    code: "PROOF_GENERATION_FAILED" | "WITNESS_GENERATION_FAILED" | "REBLIND_FAILED",
    message: string,
    cause?: unknown
  ) {
    super(code, message, cause);
    this.name = "ProofError";
  }
}

export class VerificationError extends OpenACError {
  constructor(
    code: "VERIFICATION_FAILED" | "INVALID_PROOF_FORMAT" | "COMMITMENT_MISMATCH",
    message: string,
    cause?: unknown
  ) {
    super(code, message, cause);
    this.name = "VerificationError";
  }
}

export class InputError extends OpenACError {
  constructor(
    code:
      | "INVALID_JWT"
      | "AMBIGUOUS_PAYLOAD"
      | "INVALID_KEY"
      | "INVALID_SIGNATURE"
      | "MISSING_DISCLOSURE"
      | "BIRTHDAY_NOT_FOUND"
      | "CLAIM_NOT_FOUND"
      | "CLAIM_FORMAT_MISMATCH"
      | "PARAMS_EXCEEDED"
      | "INVALID_NONCE"
      | "INVALID_ENCODING"
      | "INVALID_REVOCATION_SECRET"
      | "INVALID_REVOCATION_REGISTRY"
      | "MISSING_REVOCATION_INPUTS"
      | "CREDENTIAL_REVOKED",
    message: string,
    cause?: unknown
  ) {
    super(code, message, cause);
    this.name = "InputError";
  }
}

export class WasmError extends OpenACError {
  constructor(
    code: "WASM_LOAD_FAILED" | "WASM_OOM" | "WASM_NOT_INITIALIZED" | "KEY_LOAD_FAILED" | "KEY_INTEGRITY_FAILED" | "SETUP_NOT_SUPPORTED",
    message: string,
    cause?: unknown
  ) {
    super(code, message, cause);
    this.name = "WasmError";
  }
}
