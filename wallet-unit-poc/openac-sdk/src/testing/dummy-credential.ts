/**
 * @internal Test/dev utilities only. Uses deterministic keys and dummy issuer
 * metadata. Not for production. The main SDK entry point does not re-export
 * this module; it is reachable only via `openac-sdk/testing`.
 */
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2";

import type {
  EcdsaPublicKey,
  EcdsaPrivateKey,
} from "../types.js";
import type { VcSize } from "../sizing.js";
import { JWT_PARAMS_BY_SIZE } from "../sizing.js";
import {
  REVOCATION_VALUE_CLAIM,
  encodeRevocationValue,
  generateRevocationValue,
} from "../revocation.js";

export { JWT_PARAMS_BY_SIZE } from "../sizing.js";

const DEFAULT_ISSUER_PRIVATE_KEY_HEX =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const DEFAULT_DEVICE_PRIVATE_KEY_HEX =
  "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

export interface GenerateDummyCredentialOptions {
  size: VcSize;
  claims?: Array<{ key: string; value: string }>;
  deviceKey?: EcdsaPublicKey;
  devicePrivateKey?: EcdsaPrivateKey;
  issuerPrivateKey?: EcdsaPrivateKey;
  issuer?: string;
  nbf?: number;
  exp?: number;
  /**
   * 32-byte revocation value the issuer signs as `revocation_value`. Defaults to a
   * fresh random value, so each credential has its own revocation commitment. Pass
   * a fixed value when the JWT must be deterministic.
   */
  revocationValue?: bigint;
}

export interface DummyCredential {
  jwt: string;
  disclosures: string[];
  issuerPublicKey: EcdsaPublicKey;
  devicePublicKey: EcdsaPublicKey;
  devicePrivateKeyHex: string;
  /** The signed `revocation_value` value. */
  revocationValue: bigint;
  meta: {
    signingInputByteLength: number;
    payloadByteLength: number;
    targetSize: VcSize;
    targetMaxMessageLength: number;
  };
}

export function generateDummyCredential(
  opts: GenerateDummyCredentialOptions,
): DummyCredential {
  const params = JWT_PARAMS_BY_SIZE[opts.size];

  const issuerPrivateKey = normalizePrivateKey(
    opts.issuerPrivateKey ?? DEFAULT_ISSUER_PRIVATE_KEY_HEX,
  );
  const devicePrivateKey = normalizePrivateKey(
    opts.devicePrivateKey ?? DEFAULT_DEVICE_PRIVATE_KEY_HEX,
  );
  const devicePrivateKeyHex = bytesToHex(devicePrivateKey);

  const revocationValue = opts.revocationValue ?? generateRevocationValue();

  const issuerPublicKey = pubFromPrivate(issuerPrivateKey);
  const devicePublicKey = opts.deviceKey ?? pubFromPrivate(devicePrivateKey);

  const claimDefs =
    opts.claims ??
    [
      { key: "name", value: "Alice" },
      { key: "roc_birthday", value: "0890615" },
    ];

  // Disclosures must be >= 56 bytes (JWT ClaimHasher uses 2 SHA-256 blocks).
  const disclosures = claimDefs.map((c, i) =>
    makeDisclosure(deterministicSalt(i, 24), c.key, c.value),
  );
  const hashedClaims = disclosures.map((d) => disclosureDigest(d));

  // Cap is the tighter of maxMessageLength (less SHA-pad worst case 72 + 8)
  // and maxB64PayloadLength (less JSON syntax overhead).
  const cap = Math.min(
    params.maxMessageLength - 80,
    params.maxB64PayloadLength - 50,
  );
  const nbf = opts.nbf ?? Math.floor(Date.now() / 1000);
  const exp = opts.exp ?? nbf + 365 * 24 * 60 * 60;
  const issuer = opts.issuer ?? "https://issuer.example/";

  let signingInputLen = 0;
  let fillerCount = 0;
  while (true) {
    const extended = [...hashedClaims];
    for (let i = 0; i < fillerCount; i++) {
      extended.push(deterministicDigest(i));
    }
    const { signingInputBytes } = buildSigningInput(
      devicePublicKey,
      extended,
      issuer,
      nbf,
      exp,
      revocationValue,
    );
    signingInputLen = signingInputBytes.byteLength;
    if (signingInputLen >= cap) {
      fillerCount = Math.max(0, fillerCount - 1);
      break;
    }
    fillerCount += 1;
    if (fillerCount > 200) break;
  }

  const finalHashes = [...hashedClaims];
  for (let i = 0; i < fillerCount; i++) {
    finalHashes.push(deterministicDigest(i));
  }
  const { signingInput, signingInputBytes, payloadBytes } = buildSigningInput(
    devicePublicKey,
    finalHashes,
    issuer,
    nbf,
    exp,
    revocationValue,
  );
  const signature = signES256(signingInputBytes, issuerPrivateKey);
  const jwt = `${signingInput}.${bytesToBase64url(signature)}`;

  return {
    jwt,
    disclosures,
    issuerPublicKey,
    devicePublicKey,
    devicePrivateKeyHex,
    revocationValue,
    meta: {
      signingInputByteLength: signingInputBytes.byteLength,
      payloadByteLength: payloadBytes.byteLength,
      targetSize: opts.size,
      targetMaxMessageLength: params.maxMessageLength,
    },
  };
}

function buildSigningInput(
  devicePublicKey: EcdsaPublicKey,
  hashedClaims: string[],
  issuer: string,
  nbf: number,
  exp: number,
  revocationValue: bigint,
): { signingInput: string; signingInputBytes: Uint8Array; payloadBytes: Uint8Array } {
  const header = { alg: "ES256", typ: "vc+sd-jwt" };
  const payload = {
    sub: "did:example:subject",
    iss: issuer,
    nbf,
    exp,
    cnf: { jwk: devicePublicKey },
    [REVOCATION_VALUE_CLAIM]: encodeRevocationValue(revocationValue),
    vc: {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      type: ["VerifiableCredential"],
      credentialSubject: {
        _sd: hashedClaims,
        _sd_alg: "sha-256",
      },
    },
  };

  const headerJson = JSON.stringify(header);
  const payloadJson = JSON.stringify(payload);
  const payloadBytes = new TextEncoder().encode(payloadJson);
  const b64Header = bytesToBase64url(new TextEncoder().encode(headerJson));
  const b64Payload = bytesToBase64url(payloadBytes);
  const signingInput = `${b64Header}.${b64Payload}`;
  const signingInputBytes = new TextEncoder().encode(signingInput);
  return { signingInput, signingInputBytes, payloadBytes };
}

function pubFromPrivate(priv: Uint8Array): EcdsaPublicKey {
  const point = p256.ProjectivePoint.BASE.multiply(bytesToBigInt(priv));
  return {
    kty: "EC",
    crv: "P-256",
    x: bytesToBase64url(bigintToBytes(point.x, 32)),
    y: bytesToBase64url(bigintToBytes(point.y, 32)),
  };
}

function signES256(signingInputBytes: Uint8Array, privateKey: Uint8Array): Uint8Array {
  const msgHash = sha256(signingInputBytes);
  return p256.sign(msgHash, privateKey).toBytes("compact");
}

function makeDisclosure(salt: string, key: string, value: string): string {
  const json = JSON.stringify([salt, key, value]);
  return bytesToBase64url(new TextEncoder().encode(json));
}

function disclosureDigest(disclosure: string): string {
  return bytesToBase64url(sha256(new TextEncoder().encode(disclosure)));
}

function deterministicSalt(seed: number, len: number): string {
  const buf = sha256(new TextEncoder().encode(`openac-dummy-salt-${seed}`));
  return bytesToBase64url(buf).slice(0, len);
}

function deterministicDigest(seed: number): string {
  const buf = sha256(new TextEncoder().encode(`openac-dummy-filler-${seed}`));
  return bytesToBase64url(buf);
}

function normalizePrivateKey(key: EcdsaPrivateKey): Uint8Array {
  if (typeof key === "string") return hexToBytes(key);
  return key;
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

function bigintToBytes(value: bigint, byteLength: number): Uint8Array {
  const hex = value.toString(16).padStart(byteLength * 2, "0");
  const bytes = new Uint8Array(byteLength);
  for (let i = 0; i < byteLength; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToBase64url(bytes: Uint8Array): string {
  const B64 =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let result = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i]!;
    const b = bytes[i + 1] ?? 0;
    const c = bytes[i + 2] ?? 0;
    const triplet = (a << 16) | (b << 8) | c;
    result += B64[(triplet >> 18) & 0x3f];
    result += B64[(triplet >> 12) & 0x3f];
    result += i + 1 < bytes.length ? B64[(triplet >> 6) & 0x3f]! : "";
    result += i + 2 < bytes.length ? B64[triplet & 0x3f]! : "";
  }
  return result.replace(/\+/g, "-").replace(/\//g, "_");
}
