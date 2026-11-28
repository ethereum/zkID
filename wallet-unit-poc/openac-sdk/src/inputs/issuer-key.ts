// Decoding of an issuer public key to and from the P-256 affine coordinates the
// credential circuits use as `pubKeyX` / `pubKeyY`.
//
// issuerPublicKeyToPoint() converts a JWK or PEM key to the coordinates the
// prover puts in its witness. Proofs never reveal them (issuer hiding).

import { p256 } from "@noble/curves/nist.js";

import {
  base64urlToBase64,
  base64Decode,
  base64ToBigInt,
  base64urlEncode,
  bytesToBigInt,
} from "../utils.js";
import { InputError } from "../errors.js";
import type {
  EcdsaPublicKey,
  PemPublicKey,
  IssuerPublicKey,
} from "../types.js";
export interface IssuerKeyPoint {
  x: bigint;
  y: bigint;
}

/**
 * Convert a PEM-encoded ECDSA P-256 public key to JWK format.
 * Handles SubjectPublicKeyInfo (SPKI) format commonly used in X.509 certificates.
 */
export function pemToJwk(pem: string): EcdsaPublicKey {
  // Remove PEM headers and whitespace
  const base64 = pem
    .replace(/-----BEGIN PUBLIC KEY-----/, "")
    .replace(/-----END PUBLIC KEY-----/, "")
    .replace(/-----BEGIN EC PUBLIC KEY-----/, "")
    .replace(/-----END EC PUBLIC KEY-----/, "")
    .replace(/\s/g, "");

  const der = base64Decode(base64);

  // Find the uncompressed point in the DER structure
  // P-256 uncompressed points are 65 bytes: 0x04 || 32-byte X || 32-byte Y
  // In SPKI format, this appears after the algorithm identifier
  let pointStart = -1;
  for (let i = 0; i < der.length - 64; i++) {
    if (der[i] === 0x04 && der.length - i >= 65) {
      // Verify this looks like a valid uncompressed point position
      // The byte before 0x04 in SPKI should be the BIT STRING content
      pointStart = i;
      break;
    }
  }

  if (pointStart === -1) {
    throw new InputError(
      "INVALID_KEY",
      "Could not parse PEM public key: uncompressed point marker (0x04) not found",
    );
  }

  const x = der.slice(pointStart + 1, pointStart + 33);
  const y = der.slice(pointStart + 33, pointStart + 65);

  // Validate the point is on the P-256 curve
  const xBigInt = bytesToBigInt(x);
  const yBigInt = bytesToBigInt(y);

  try {
    p256.ProjectivePoint.fromAffine({ x: xBigInt, y: yBigInt });
  } catch {
    throw new InputError(
      "INVALID_KEY",
      "PEM public key is not a valid P-256 curve point",
    );
  }

  return {
    kty: "EC",
    crv: "P-256",
    x: base64urlEncode(x),
    y: base64urlEncode(y),
  };
}

/**
 * Decode a JWK- or PEM-encoded issuer public key into affine coordinates.
 * Throws `InputError("INVALID_KEY")` for anything that is not a valid P-256
 * point.
 */
export function issuerPublicKeyToPoint(key: IssuerPublicKey): IssuerKeyPoint {
  let x: bigint;
  let y: bigint;

  if ("pem" in key) {
    const jwk = pemToJwk((key as PemPublicKey).pem);
    x = base64ToBigInt(base64urlToBase64(jwk.x));
    y = base64ToBigInt(base64urlToBase64(jwk.y));
  } else {
    const jwk = key as EcdsaPublicKey;
    if (jwk.kty !== "EC" || jwk.crv !== "P-256") {
      throw new InputError(
        "INVALID_KEY",
        "Issuer public key must be P-256 EC key",
      );
    }
    x = base64ToBigInt(base64urlToBase64(jwk.x));
    y = base64ToBigInt(base64urlToBase64(jwk.y));
  }

  try {
    p256.ProjectivePoint.fromAffine({ x, y }).assertValidity();
  } catch {
    throw new InputError(
      "INVALID_KEY",
      "Issuer public key is not a valid P-256 curve point",
    );
  }

  return { x, y };
}


/**
 * An issuer key as a validated point: decodes a JWK or PEM key, or checks a given
 * point is on P-256 with coordinates below p, the only encoding the Show circuit
 * accepts. Throws `InputError("INVALID_KEY")` otherwise.
 */
export function toIssuerKeyPoint(key: IssuerPublicKey | IssuerKeyPoint): IssuerKeyPoint {
  if (!("x" in key && typeof key.x === "bigint")) {
    return issuerPublicKeyToPoint(key as IssuerPublicKey);
  }
  const { x, y } = key as IssuerKeyPoint;
  try {
    p256.ProjectivePoint.fromAffine({ x, y }).assertValidity();
  } catch {
    throw new InputError("INVALID_KEY", "Issuer key is not a valid P-256 curve point");
  }
  return { x, y };
}
