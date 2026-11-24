import { p256 } from "@noble/curves/p256";
import { Field } from "@noble/curves/abstract/modular";
import { sha256 } from "@noble/hashes/sha2";
import { sha256Pad } from "@zk-email/helpers";
import { strict as assert } from "assert";
import { poseidon2 } from "./poseidon-p256.ts";

// Mirrors circuits/jsonld.circom: JSONLD(maxDocLen, maxClaims, maxSubjLen, maxNameLen, maxValueLen, maxDeviceKeyLen).
export interface JsonLdParams {
  maxDocLen: number;
  maxClaims: number;
  maxSubjLen: number;
  maxNameLen: number;
  maxValueLen: number;
  maxDeviceKeyLen: number;
}

export const JSONLD_DEFAULT_PARAMS: JsonLdParams = {
  maxDocLen: 2240,
  maxClaims: 2,
  maxSubjLen: 128,
  maxNameLen: 31,
  maxValueLen: 64,
  maxDeviceKeyLen: 252,
};

export const JSONLD_FORMAT = { bool: 0, uint: 1, isoDate: 2, rocDate: 3, string: 4, digest64: 5 } as const;

// Width Show hashes predicate attribute names over (show.circom NAME_ID_LEN).
const NAME_ID_LEN = 31;
const MAX_UINT_DIGITS = 19;
const MAX_DIGEST_VALUE_LEN = 55;
const JWK_COORD_B64_LEN = 43;

export const JSONLD_BASE = "https://example.org/eid#";

export const SIGNING_HEADER_B64 = Buffer.from('{"alg":"ES256","b64":false,"crit":["b64"]}').toString("base64url");

const CREDENTIAL_SUBJECT_MARK = " <https://www.w3.org/2018/credentials#credentialSubject> <";
const P256_ORDER = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
const Fn = Field(P256_ORDER);
const MASK_64 = (1n << 64n) - 1n;

export interface JsonLdClaimRequest {
  name: string;
  format: number;
}

export interface BuildJsonLdInputsArgs {
  nquads: string;
  proofHash: Uint8Array;
  signature: { r: bigint; s: bigint } | { jws: string };
  issuerPublicKey: { x: bigint; y: bigint };
  base: string;
  claims: JsonLdClaimRequest[];
  params?: Partial<JsonLdParams>;
}

export interface JsonLdPrepareMeta {
  normalizedClaimValues: bigint[];
  claimIdentifierHashes: bigint[];
  deviceKey: { x: bigint; y: bigint };
  docHash: Uint8Array;
  subject: string;
}

const UTF8 = new TextEncoder();

function bytesToBigInt(bytes: Uint8Array): bigint {
  return bytes.reduce((n, b) => (n << 8n) | BigInt(b), 0n);
}

function bigIntToBytes32(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--, n >>= 8n) out[i] = Number(n & 0xffn);
  return out;
}

function padTo(bytes: ArrayLike<number>, len: number): bigint[] {
  assert.ok(bytes.length <= len, `${bytes.length} bytes do not fit in ${len}`);
  const out = new Array<bigint>(len).fill(0n);
  for (let i = 0; i < bytes.length; i++) out[i] = BigInt(bytes[i]);
  return out;
}

function indexOfAll(hay: Uint8Array, needle: Uint8Array): number[] {
  const hits: number[] = [];
  outer: for (let i = 0; i + needle.length <= hay.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    hits.push(i);
  }
  return hits;
}

/**
 * H(name) as the circuits compute it: HashBytesToFieldWithLen over a 31-byte
 * zero-padded buffer, i.e. Poseidon(2)([LE-packed name, length]) over secq256r1.
 */
export function claimIdentifierHash(name: string): bigint {
  const raw = UTF8.encode(name);
  assert.ok(raw.length <= NAME_ID_LEN, `Claim name "${name}" exceeds ${NAME_ID_LEN} bytes`);
  let packed = 0n;
  for (let i = 0; i < raw.length; i++) packed += BigInt(raw[i]) << BigInt(8 * i);
  return poseidon2(packed, BigInt(raw.length));
}

/** Mirrors components/jsonld-value-normalizer.circom. */
export function normalizeJsonLdValue(format: number, value: string): bigint {
  const raw = UTF8.encode(value);
  switch (format) {
    case JSONLD_FORMAT.bool:
      return value === "1" || value === "true" ? 1n : 0n;
    case JSONLD_FORMAT.uint:
      assert.ok(/^[0-9]{1,19}$/.test(value), `uint value must be 1..${MAX_UINT_DIGITS} digits: "${value}"`);
      return BigInt(value);
    case JSONLD_FORMAT.isoDate:
      assert.ok(/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(value), `iso_date value must be YYYY-MM-DD: "${value}"`);
      return BigInt(value.replaceAll("-", ""));
    case JSONLD_FORMAT.rocDate:
      assert.ok(/^[0-9]{7}$/.test(value), `roc_date value must be YYYMMDD: "${value}"`);
      return BigInt(value);
    case JSONLD_FORMAT.string:
      assert.ok(raw.length <= 8, `string value packs into 64 bits, at most 8 bytes: "${value}"`);
      assert.ok(raw.length === 0 || raw[0] !== 0, "string value must not start with NUL");
      return bytesToBigInt(raw);
    case JSONLD_FORMAT.digest64: {
      assert.ok(raw.length <= MAX_DIGEST_VALUE_LEN, `digest64 value exceeds ${MAX_DIGEST_VALUE_LEN} bytes`);
      // Low 64 bits of SHA-256(value) read as a big-endian 256-bit integer.
      return bytesToBigInt(sha256(raw)) & MASK_64;
    }
    default:
      throw new Error(`unknown claim format ${format}`);
  }
}

function assertSubject(subject: string): void {
  assert.ok(subject.length >= 1, "credentialSubject IRI is empty");
  assert.ok(!/[<> "\\\n\r]/.test(subject), "credentialSubject IRI contains a character the circuit forbids");
}

function assertPlainValue(value: string, what: string): void {
  assert.ok(!/["\\\n\r]/.test(value), `${what}: value contains a quote, backslash or line break (escapes are not supported)`);
}

interface Line {
  start: number;
  text: string;
}

function splitLines(doc: Uint8Array): Line[] {
  assert.ok(doc.length > 0 && doc[doc.length - 1] === 0x0a, "N-Quads document must end with a line feed");
  const lines: Line[] = [];
  let start = 0;
  for (let i = 0; i < doc.length; i++) {
    if (doc[i] === 0x0a) {
      lines.push({ start, text: Buffer.from(doc.subarray(start, i)).toString("utf8") });
      start = i + 1;
    }
  }
  return lines;
}

function parseSignature(sig: BuildJsonLdInputsArgs["signature"]): { r: bigint; s: bigint } {
  if ("jws" in sig) {
    const parts = sig.jws.split(".");
    assert.equal(parts.length, 3, "jws must be a compact detached JWS: header..signature");
    assert.equal(parts[0], SIGNING_HEADER_B64, "jws header must be the RFC 7797 ES256 header the circuit pins");
    assert.equal(parts[1], "", "jws payload must be detached");
    const raw = Buffer.from(parts[2], "base64url");
    assert.equal(raw.length, 64, `jws signature must be 64 bytes (r||s), got ${raw.length}`);
    return { r: bytesToBigInt(raw.subarray(0, 32)), s: bytesToBigInt(raw.subarray(32)) };
  }
  return sig;
}

export function jsonLdSigningInput(proofHash: Uint8Array, docHash: Uint8Array): Uint8Array {
  const hdr = UTF8.encode(SIGNING_HEADER_B64 + ".");
  const out = new Uint8Array(hdr.length + 64);
  out.set(hdr, 0);
  out.set(proofHash, hdr.length);
  out.set(docHash, hdr.length + 32);
  return out;
}

export function buildJsonLdPrepareInputs(args: BuildJsonLdInputsArgs) {
  const params: JsonLdParams = { ...JSONLD_DEFAULT_PARAMS, ...args.params };
  const { nquads, proofHash, issuerPublicKey, base, claims } = args;

  assert.equal(proofHash.length, 32, "proofHash must be 32 bytes");
  assert.ok(claims.length <= params.maxClaims, `Too many claims: ${claims.length} > ${params.maxClaims}`);
  assert.ok(new Set(claims.map((c) => c.name)).size === claims.length, "duplicate claim names requested");
  assert.equal(base, JSONLD_BASE, "base must equal the circuit's BASE constant");

  const doc = UTF8.encode(nquads);
  const lines = splitLines(doc);

  // CS line: exactly one, so csPos cannot be aimed at a look-alike.
  const csLines = lines.filter((l) => l.text.includes(CREDENTIAL_SUBJECT_MARK));
  assert.equal(csLines.length, 1, `expected exactly one credentialSubject line, found ${csLines.length}`);
  const csLine = csLines[0];
  const csRest = csLine.text.slice(csLine.text.indexOf(CREDENTIAL_SUBJECT_MARK) + CREDENTIAL_SUBJECT_MARK.length);
  assert.ok(csRest.endsWith("> ."), "credentialSubject object must be an IRI");
  const subject = csRest.slice(0, -3);
  assertSubject(subject);
  const subjectBytes = UTF8.encode(subject);
  assert.ok(subjectBytes.length <= params.maxSubjLen, `subject too long: ${subjectBytes.length} > ${params.maxSubjLen}`);
  const csPos = csLine.start + UTF8.encode(csLine.text.slice(0, csLine.text.indexOf(CREDENTIAL_SUBJECT_MARK))).length;

  const lineFor = (name: string): { line: Line; value: string } => {
    const prefix = `<${subject}> <${base}${name}> `;
    const hits = lines.filter((l) => l.text.startsWith(prefix));
    assert.equal(hits.length, 1, `claim "${name}" must occur on exactly one line, found ${hits.length}`);
    const m = /^"(.*)" \.$/.exec(hits[0].text.slice(prefix.length));
    assert.ok(m, `claim "${name}" is not a plain string literal`);
    assertPlainValue(m[1], `claim "${name}"`);
    return { line: hits[0], value: m[1] };
  };

  // Device key line and JWK anchors.
  const dk = lineFor("deviceKey");
  assert.ok(/^[A-Za-z0-9_-]+$/.test(dk.value), "deviceKey value must be base64url");
  const dkBytes = UTF8.encode(dk.value);
  assert.ok(dkBytes.length <= params.maxDeviceKeyLen, `deviceKey too long: ${dkBytes.length} > ${params.maxDeviceKeyLen}`);
  const jwkBytes = Buffer.from(dk.value, "base64url");
  const jwkText = jwkBytes.toString("latin1");
  const anchorPos = (anchor: string): number => {
    const hits = indexOfAll(jwkBytes, UTF8.encode(anchor));
    assert.equal(hits.length, 1, `JWK anchor ${anchor} must occur exactly once, found ${hits.length}`);
    return hits[0];
  };
  const jwkXPos = anchorPos('"x":"');
  const jwkYPos = anchorPos('"y":"');
  const coord = (pos: number): bigint => {
    const start = pos + 5;
    assert.equal(jwkText[start + JWK_COORD_B64_LEN], '"', "JWK coordinate must be exactly 43 base64url characters");
    const b64 = jwkText.slice(start, start + JWK_COORD_B64_LEN);
    assert.ok(/^[A-Za-z0-9_-]{43}$/.test(b64), "JWK coordinate is not base64url");
    return bytesToBigInt(Buffer.from(b64, "base64url"));
  };
  const deviceKey = { x: coord(jwkXPos), y: coord(jwkYPos) };

  // Claim slots.
  const linePos: bigint[] = [];
  const names: bigint[][] = [];
  const nameLengths: bigint[] = [];
  const values: bigint[][] = [];
  const valueLengths: bigint[] = [];
  const claimFormats: bigint[] = [];
  const claimFlags: bigint[] = [];
  const normalizedClaimValues: bigint[] = [];
  const claimIdentifierHashes: bigint[] = [];

  for (let i = 0; i < params.maxClaims; i++) {
    const claim = claims[i];
    if (!claim) {
      linePos.push(0n);
      names.push(padTo([], params.maxNameLen));
      nameLengths.push(0n);
      values.push(padTo([], params.maxValueLen));
      valueLengths.push(0n);
      claimFormats.push(0n);
      claimFlags.push(0n);
      normalizedClaimValues.push(0n);
      claimIdentifierHashes.push(0n);
      continue;
    }
    assert.ok(/^[A-Za-z0-9_]+$/.test(claim.name), `claim name "${claim.name}" must be [A-Za-z0-9_]+`);
    const nameBytes = UTF8.encode(claim.name);
    assert.ok(nameBytes.length <= params.maxNameLen, `claim name "${claim.name}" too long: ${nameBytes.length} > ${params.maxNameLen}`);
    const { line, value } = lineFor(claim.name);
    const valueBytes = UTF8.encode(value);
    assert.ok(valueBytes.length <= params.maxValueLen, `value of "${claim.name}" too long: ${valueBytes.length} > ${params.maxValueLen}`);
    linePos.push(BigInt(line.start));
    names.push(padTo(nameBytes, params.maxNameLen));
    nameLengths.push(BigInt(nameBytes.length));
    values.push(padTo(valueBytes, params.maxValueLen));
    valueLengths.push(BigInt(valueBytes.length));
    claimFormats.push(BigInt(claim.format));
    claimFlags.push(1n);
    normalizedClaimValues.push(normalizeJsonLdValue(claim.format, value));
    claimIdentifierHashes.push(claimIdentifierHash(claim.name));
  }

  // Doc, hashes, signature.
  assert.ok(doc.length + 9 <= params.maxDocLen, `document too long: ${doc.length} bytes for maxDocLen ${params.maxDocLen}`);
  const [docPadded, docPaddedLen] = sha256Pad(doc, params.maxDocLen);
  const docHash = new Uint8Array(sha256(doc));

  const { r, s } = parseSignature(args.signature);
  const pubRaw = new Uint8Array(65);
  pubRaw[0] = 4;
  pubRaw.set(bigIntToBytes32(issuerPublicKey.x), 1);
  pubRaw.set(bigIntToBytes32(issuerPublicKey.y), 33);
  const sigRaw = new Uint8Array(64);
  sigRaw.set(bigIntToBytes32(r), 0);
  sigRaw.set(bigIntToBytes32(s), 32);
  const ok = p256.verify(sigRaw, sha256(jsonLdSigningInput(proofHash, docHash)), pubRaw, { lowS: false });
  assert.ok(ok, "issuer signature does not verify over the signing input");

  const inputs = {
    doc: Array.from(docPadded, (b) => BigInt(b)),
    docLength: BigInt(docPaddedLen),
    proofHash: Array.from(proofHash, (b) => BigInt(b)),
    sig_r: r,
    sig_s_inverse: Fn.inv(s),
    pubKeyX: issuerPublicKey.x,
    pubKeyY: issuerPublicKey.y,
    subject: padTo(subjectBytes, params.maxSubjLen),
    subjectLength: BigInt(subjectBytes.length),
    csPos: BigInt(csPos),
    deviceKeyLinePos: BigInt(dk.line.start),
    deviceKeyValue: padTo(dkBytes, params.maxDeviceKeyLen),
    deviceKeyValueLength: BigInt(dkBytes.length),
    jwkXPos: BigInt(jwkXPos),
    jwkYPos: BigInt(jwkYPos),
    linePos,
    names,
    nameLengths,
    values,
    valueLengths,
    claimFormats,
    claimFlags,
  };

  const meta: JsonLdPrepareMeta = { normalizedClaimValues, claimIdentifierHashes, deviceKey, docHash, subject };
  return { inputs, meta };
}
