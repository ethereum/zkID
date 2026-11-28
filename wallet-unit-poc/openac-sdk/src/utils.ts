import { sha256 } from "@noble/hashes/sha2";

import { InputError } from "./errors.js";

// secp256r1 (P-256) scalar field order
export const P256_SCALAR_ORDER = BigInt(
  "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
);

const B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const B64_LOOKUP = new Uint8Array(128).fill(0xff);
for (let i = 0; i < B64_CHARS.length; i++) {
  B64_LOOKUP[B64_CHARS.charCodeAt(i)] = i;
}

export function base64urlToBase64(b64url: string): string {
  let b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const pad = (4 - (b64.length % 4)) % 4;
  return b64 + "=".repeat(pad);
}

export function base64ToBase64url(b64: string): string {
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64Decode(b64: string): Uint8Array {
  const normalized = base64urlToBase64(b64);
  const stripped = normalized.replace(/=+$/, "");
  const outLen = Math.floor((stripped.length * 3) / 4);
  const out = new Uint8Array(outLen);

  let bits = 0;
  let value = 0;
  let outIdx = 0;

  for (let i = 0; i < stripped.length; i++) {
    const charCode = stripped.charCodeAt(i);
    const decoded = charCode < 128 ? B64_LOOKUP[charCode]! : 0xff;
    if (decoded === 0xff) {
      throw new InputError("INVALID_ENCODING", `Invalid base64 character '${stripped[i]}'`);
    }
    value = (value << 6) | decoded;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[outIdx++] = (value >> bits) & 0xff;
    }
  }

  return out;
}

export function base64Encode(bytes: Uint8Array): string {
  let result = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i]!;
    const b = bytes[i + 1] ?? 0;
    const c = bytes[i + 2] ?? 0;

    const triplet = (a << 16) | (b << 8) | c;

    result += B64_CHARS[(triplet >> 18) & 0x3f];
    result += B64_CHARS[(triplet >> 12) & 0x3f];
    result += i + 1 < bytes.length ? B64_CHARS[(triplet >> 6) & 0x3f] : "=";
    result += i + 2 < bytes.length ? B64_CHARS[triplet & 0x3f] : "=";
  }
  return result;
}

export function base64urlEncode(bytes: Uint8Array): string {
  return base64ToBase64url(base64Encode(bytes));
}

export function bytesToBigInt(bytes: Uint8Array): bigint {
  let hex = "";
  for (const b of bytes) {
    hex += b.toString(16).padStart(2, "0");
  }
  if (hex.length === 0) return 0n;
  return BigInt("0x" + hex);
}

/** Big-endian bytes of `value`; throws if it is negative or does not fit in `byteLength` bytes. */
export function bigintToBytes(value: bigint, byteLength: number): Uint8Array {
  if (value < 0n || value >= 1n << BigInt(byteLength * 8)) {
    throw new RangeError(`${value} does not fit in ${byteLength} bytes`);
  }
  const hex = value.toString(16).padStart(byteLength * 2, "0");
  const bytes = new Uint8Array(byteLength);
  for (let i = 0; i < byteLength; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function base64ToBigInt(b64: string): bigint {
  return bytesToBigInt(base64Decode(b64));
}

export function base64urlToBigInt(b64url: string): bigint {
  return base64ToBigInt(base64urlToBase64(b64url));
}

export function bigintToBase64url(value: bigint): string {
  return base64urlEncode(bigintToBytes(value, 32));
}

export function uint8ArrayToBigIntArray(data: Uint8Array): bigint[] {
  return Array.from(data, (b) => BigInt(b));
}

export function stringToPaddedBigIntArray(s: string, padLength: number): bigint[] {
  const values = Array.from(s, (char) => BigInt(char.charCodeAt(0)));
  while (values.length < padLength) {
    values.push(0n);
  }
  return values;
}

// SHA-256 message padding matching @zk-email/helpers sha256Pad
export function sha256Pad(msg: Uint8Array, maxLength: number): [Uint8Array, number] {
  const msgLen = msg.length;
  const blockSize = 64;
  const bitLength = BigInt(msgLen) * 8n;

  let paddedLen = msgLen + 1 + 8;
  paddedLen = Math.ceil(paddedLen / blockSize) * blockSize;

  if (paddedLen > maxLength) {
    throw new Error(`Message too long for maxLength=${maxLength}: needs ${paddedLen} bytes`);
  }

  const padded = new Uint8Array(maxLength);
  padded.set(msg);
  padded[msgLen] = 0x80;

  // Write bit length as big-endian 64-bit at the end of the last 64-byte block
  const lenPos = paddedLen - 8;
  const bitLenHigh = Number((bitLength >> 32n) & 0xffffffffn);
  const bitLenLow = Number(bitLength & 0xffffffffn);
  padded[lenPos] = (bitLenHigh >> 24) & 0xff;
  padded[lenPos + 1] = (bitLenHigh >> 16) & 0xff;
  padded[lenPos + 2] = (bitLenHigh >> 8) & 0xff;
  padded[lenPos + 3] = bitLenHigh & 0xff;
  padded[lenPos + 4] = (bitLenLow >> 24) & 0xff;
  padded[lenPos + 5] = (bitLenLow >> 16) & 0xff;
  padded[lenPos + 6] = (bitLenLow >> 8) & 0xff;
  padded[lenPos + 7] = bitLenLow & 0xff;

  return [padded, paddedLen];
}

export function sha256Hash(data: Uint8Array): Uint8Array {
  return sha256(data);
}

export function sha256HashString(str: string): Uint8Array {
  return sha256(new TextEncoder().encode(str));
}

// Encode claims with SHA-256 padding for circuit input
export function encodeClaims(
  claims: string[],
  maxClaims: number,
  maxClaimsLength: number
): { claimArray: bigint[][]; claimLengths: bigint[] } {
  const claimArray: bigint[][] = Array(maxClaims)
    .fill(null)
    .map(() => Array(maxClaimsLength).fill(0n) as bigint[]);
  const claimLengths: bigint[] = Array(maxClaims).fill(0n) as bigint[];

  for (let i = 0; i < claims.length && i < maxClaims; i++) {
    const claim = claims[i]!;
    const utf8Bytes = new TextEncoder().encode(claim);
    const [paddedBytes] = sha256Pad(utf8Bytes, maxClaimsLength);

    for (let j = 0; j < paddedBytes.length && j < maxClaimsLength; j++) {
      claimArray[i]![j] = BigInt(paddedBytes[j]!);
    }

    claimLengths[i] = BigInt(claim.length);
  }

  return { claimArray, claimLengths };
}

// Modular inverse using extended Euclidean algorithm
export function modInverse(a: bigint, m: bigint): bigint {
  let [old_r, r] = [a % m, m];
  let [old_s, s] = [1n, 0n];

  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }

  if (old_r !== 1n) {
    throw new Error("Modular inverse does not exist");
  }

  return ((old_s % m) + m) % m;
}

export function modScalarField(value: bigint): bigint {
  return ((value % P256_SCALAR_ORDER) + P256_SCALAR_ORDER) % P256_SCALAR_ORDER;
}

export function utf8Decode(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

export function utf8Encode(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

export function circuitInputsToJson(inputs: object): string {
  return JSON.stringify(inputs, (_key, value) => {
    if (typeof value === "bigint") {
      return value.toString();
    }
    return value;
  });
}

export function jwkPointToBigInt(jwk: { x: string; y: string }): { x: bigint; y: bigint } {
  return {
    x: base64urlToBigInt(jwk.x),
    y: base64urlToBigInt(jwk.y),
  };
}
