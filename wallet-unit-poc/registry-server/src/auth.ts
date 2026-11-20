import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/** A fresh bearer token: 32 random bytes, base64url. */
export function generateToken(): string {
  return randomBytes(32).toString("base64url");
}

/** Tokens are stored as their SHA-256, hex. */
export function hashToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

/** Constant-time comparison of a presented token against a stored hash. */
export function tokenMatches(token: string, tokenHash: string): boolean {
  const presented = Buffer.from(hashToken(token), "hex");
  const stored = Buffer.from(tokenHash, "hex");
  return presented.length === stored.length && timingSafeEqual(presented, stored);
}

/** The token in an `Authorization: Bearer <token>` header. */
export function bearerToken(header: string | undefined): string | undefined {
  const match = header ? /^Bearer\s+(\S+)$/i.exec(header) : null;
  return match?.[1];
}
