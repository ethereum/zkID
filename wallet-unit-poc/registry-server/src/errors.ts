export type RegistryErrorCode =
  | "INVALID_INPUT"
  | "UNAUTHORIZED"
  | "FORBIDDEN"
  | "NOT_FOUND"
  | "METHOD_NOT_ALLOWED"
  | "MAX_DEPTH_EXCEEDED"
  | "PAYLOAD_TOO_LARGE"
  | "STORAGE_FAILED";

/** A rejected registry operation. The server maps `code` to an HTTP status. */
export class RegistryError extends Error {
  constructor(
    readonly code: RegistryErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "RegistryError";
  }
}

/** Errors thrown by the tree libraries (duplicates, unknown commitments, range) are input errors. */
export function toRegistryError(error: unknown): RegistryError {
  if (error instanceof RegistryError) return error;
  return new RegistryError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
}
