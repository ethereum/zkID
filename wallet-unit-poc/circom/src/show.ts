import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2";
import { Field } from "@noble/curves/abstract/modular";
import { strict as assert } from "assert";
import type { JwkEcdsaPublicKey } from "./es256.ts";
import type { JwtCircuitParams } from "./jwt.ts";
import { base64urlToBigInt, base64urlToBase64, bufferToBigInt } from "./utils.ts";
import {
  DEFAULT_TEST_ISSUER,
  generateIssuerMembershipInputs,
  type IssuerMembershipInputs,
} from "./issuer-hiding.ts";

export const LogicToken = {
  AND: 2,
  OR: 3,
  NOT: 4,
  PRED_BASE: 6,
} as const;

/** Fixed byte width the circuit hashes an attribute name over (jwt.circom NAME_ID_LEN). */
export const NAME_ID_LEN = 31;

/** UTF-8 encode a claim name into a fixed NAME_ID_LEN byte buffer + length. */
export function nameToBuffer(name: string): { bytes: bigint[]; len: bigint } {
  const raw = Array.from(new TextEncoder().encode(name));
  assert.ok(raw.length <= NAME_ID_LEN, `Claim name "${name}" exceeds ${NAME_ID_LEN} bytes`);
  const bytes = raw.map((b) => BigInt(b));
  while (bytes.length < NAME_ID_LEN) bytes.push(0n);
  return { bytes, len: BigInt(raw.length) };
}

export function predicateToken(j: number): number {
  return LogicToken.PRED_BASE + j;
}

export interface ShowCircuitParams {
  nClaims: number;
  maxPredicates: number;
  maxLogicTokens: number;
  valueBits: number;
  maxIssuerDepth: number;
}

export function generateShowCircuitParams(params: number[] | JwtCircuitParams): ShowCircuitParams {
  const nClaims = Array.isArray(params) ? Math.max(1, (params[2] || 2) - 2) : Math.max(1, (params.maxMatches || 2) - 2);
  const maxPredicates = 2;
  const maxLogicTokens = 8;
  const valueBits = 64;

  return { nClaims, maxPredicates, maxLogicTokens, valueBits, maxIssuerDepth: 8 };
}

export function signDeviceNonce(message: string, privateKey: Uint8Array | string): string {
  const privateKeyBytes = typeof privateKey === "string" ? Buffer.from(privateKey, "hex") : privateKey;
  const messageHash = sha256(message);
  const signature = p256.sign(messageHash, privateKeyBytes);
  return Buffer.from(signature.toCompactRawBytes()).toString("base64url");
}

function decodeClaimComparableValue(claim: string): bigint {
  const packAsciiBigEndian = (text: string): bigint => {
    return Array.from(text).reduce((acc, ch) => acc * 256n + BigInt(ch.charCodeAt(0)), 0n);
  };

  const decoded = Buffer.from(base64urlToBase64(claim), "base64").toString("utf8");
  const parsed = JSON.parse(decoded);

  let rawValue: unknown = parsed;
  if (Array.isArray(parsed) && parsed.length >= 3) {
    rawValue = parsed[2];
  }

  if (typeof rawValue === "number") {
    assert.ok(Number.isInteger(rawValue), "Numeric claim value must be an integer");
    return BigInt(rawValue);
  }

  if (typeof rawValue === "string") {
    const trimmed = rawValue.trim();
    if (trimmed === "1" || trimmed.toLowerCase() === "true") return 1n;
    if (trimmed === "0" || trimmed.toLowerCase() === "false") return 0n;

    if (/^\d+$/.test(trimmed)) {
      return BigInt(trimmed);
    }

    const packed = packAsciiBigEndian(trimmed);
    assert.ok(packed < 2n ** 64n, `String "${trimmed}" packs to more than 64 bits; limit string values to 8 ASCII characters`);
    return packed;
  }

  throw new Error("Unsupported claim value type for generalized predicate comparison");
}

export function generateShowInputs(
  params: ShowCircuitParams,
  nonce: string,
  deviceSignature: string,
  deviceKey: JwkEcdsaPublicKey,
  encodedClaims: string[] = [],
  logicExpr: number[] = [],
  normalizedClaimValues: bigint[] = [],
  // Default 0 leaves the binding vacuous for flows with no attribute names (JWT);
  // mdoc callers pass real hashes.
  claimIdentifierHashes: bigint[] = [],
  // Must carry the credential's real issuer key when linked to a Prepare proof.
  issuer?: IssuerMembershipInputs
): IssuerMembershipInputs & {
  deviceKeyX: bigint;
  deviceKeyY: bigint;
  sig_r: bigint;
  sig_s_inverse: bigint;
  messageHash: bigint;
  predicateLen: bigint;
  claimValues: bigint[];
  predicateClaimRefs: bigint[];
  predicateOps: bigint[];
  predicateRhsIsRef: bigint[];
  predicateRhsValues: bigint[];
  claimIdentifierHashes: bigint[];
  predicateClaimNames: bigint[][];
  predicateClaimNameLens: bigint[];
  predicateRhsClaimNames: bigint[][];
  predicateRhsClaimNameLens: bigint[];
  tokenTypes: bigint[];
  tokenValues: bigint[];
  exprLen: bigint;
} {
  const sig = Buffer.from(deviceSignature, "base64url");
  const sig_decoded = p256.Signature.fromCompact(sig.toString("hex"));
  const Fq = Field(BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"));
  const sig_s_inverse = Fq.inv(sig_decoded.s);

  assert.ok(deviceKey.kty === "EC" && deviceKey.crv === "P-256", "Device key must be P-256 EC");
  const deviceKeyX = base64urlToBigInt(deviceKey.x);
  const deviceKeyY = base64urlToBigInt(deviceKey.y);

  const pubkey = new p256.Point(deviceKeyX, deviceKeyY, 1n);
  const isValid = p256.verify(sig, sha256(nonce), pubkey.toRawBytes());
  assert.ok(isValid, "Device signature verification failed");

  const messageHash = sha256(nonce);
  const messageHashBigInt = bufferToBigInt(Buffer.from(messageHash));
  const scalarFieldOrder = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
  const messageHashModQ = messageHashBigInt % scalarFieldOrder;

  const decodedClaimValues = encodedClaims.map((encoded) => decodeClaimComparableValue(encoded));

  if (normalizedClaimValues.length > 0 && decodedClaimValues.length > 0) {
    assert.strictEqual(
      decodedClaimValues.length,
      normalizedClaimValues.length,
      `encodedClaims count (${decodedClaimValues.length}) must match normalizedClaimValues count (${normalizedClaimValues.length})`
    );

    for (let i = 0; i < decodedClaimValues.length; i++) {
      assert.strictEqual(
        decodedClaimValues[i],
        normalizedClaimValues[i],
        `encodedClaims[${i}] normalized value (${decodedClaimValues[i]}) must equal normalizedClaimValues[${i}] (${normalizedClaimValues[i]})`
      );
    }
  }

  const normalizedValues =
    normalizedClaimValues.length > 0
      ? normalizedClaimValues
      : decodedClaimValues.length > 0
        ? decodedClaimValues
        : [0n];
  const primaryClaimValue = normalizedValues[0] ?? 0n;

  assert.ok(
    params.nClaims >= params.maxPredicates,
    `nClaims (${params.nClaims}) must be >= maxPredicates (${params.maxPredicates})`
  );

  const claimValues = Array(params.nClaims).fill(0n);
  const predicateClaimRefs = Array(params.maxPredicates).fill(0n);
  const predicateOps = Array(params.maxPredicates).fill(2n);
  const predicateRhsIsRef = Array(params.maxPredicates).fill(0n);
  const predicateRhsValues = Array(params.maxPredicates).fill(primaryClaimValue);
  const claimIdHashes = Array(params.nClaims).fill(0n);
  for (let i = 0; i < Math.min(params.nClaims, claimIdentifierHashes.length); i++) {
    claimIdHashes[i] = claimIdentifierHashes[i];
  }
  // Verifier attribute-name inputs (public). The Show circuit hashes them to the
  // required identity, so the caller sets the name for each active predicate
  // after the predicate program is filled. Unused slots stay zero-length.
  const emptyName = (): bigint[] => Array(NAME_ID_LEN).fill(0n);
  const predicateClaimNames = Array.from({ length: params.maxPredicates }, emptyName);
  const predicateClaimNameLens = Array(params.maxPredicates).fill(0n);
  const predicateRhsClaimNames = Array.from({ length: params.maxPredicates }, emptyName);
  const predicateRhsClaimNameLens = Array(params.maxPredicates).fill(0n);

  assert.ok(
    normalizedValues.length <= params.nClaims,
    `Number of normalized claim values (${normalizedValues.length}) exceeds nClaims (${params.nClaims})`
  );

  for (let i = 0; i < Math.min(params.nClaims, normalizedValues.length); i++) {
    claimValues[i] = normalizedValues[i];
  }

  claimValues[0] = primaryClaimValue;

  const compactExpr = logicExpr.length === 0 ? [predicateToken(0)] : logicExpr;
  const tokenTypesCompact: number[] = [];
  const tokenValuesCompact: number[] = [];

  for (const tok of compactExpr) {
    if (tok >= LogicToken.PRED_BASE) {
      const ref = tok - LogicToken.PRED_BASE;
      assert.ok(ref >= 0 && ref < params.maxPredicates, `Predicate ref ${ref} is out of range`);
      tokenTypesCompact.push(0);
      tokenValuesCompact.push(ref);
      continue;
    }

    if (tok === LogicToken.AND) {
      tokenTypesCompact.push(1);
      tokenValuesCompact.push(0);
      continue;
    }

    if (tok === LogicToken.OR) {
      tokenTypesCompact.push(2);
      tokenValuesCompact.push(0);
      continue;
    }

    if (tok === LogicToken.NOT) {
      tokenTypesCompact.push(3);
      tokenValuesCompact.push(0);
      continue;
    }

    throw new Error(`Unsupported legacy logic token ${tok}. Use predicate refs and AND/OR/NOT operators.`);
  }

  const exprLen = BigInt(tokenTypesCompact.length);
  assert.ok(tokenTypesCompact.length <= params.maxLogicTokens, "Expression exceeds maxLogicTokens");

  const tokenTypes = [
    ...tokenTypesCompact,
    ...Array(params.maxLogicTokens - tokenTypesCompact.length).fill(0),
  ].map(BigInt);

  const tokenValues = [
    ...tokenValuesCompact,
    ...Array(params.maxLogicTokens - tokenValuesCompact.length).fill(0),
  ].map(BigInt);

  return {
    deviceKeyX,
    deviceKeyY,
    sig_r: sig_decoded.r,
    sig_s_inverse,
    messageHash: messageHashModQ,
    predicateLen: 1n,
    claimValues,
    predicateClaimRefs,
    predicateOps,
    predicateRhsIsRef,
    predicateRhsValues,
    claimIdentifierHashes: claimIdHashes,
    predicateClaimNames,
    predicateClaimNameLens,
    predicateRhsClaimNames,
    predicateRhsClaimNameLens,
    tokenTypes,
    tokenValues,
    exprLen,
    ...(issuer ?? generateIssuerMembershipInputs(DEFAULT_TEST_ISSUER, undefined, params.maxIssuerDepth)),
  };
}
