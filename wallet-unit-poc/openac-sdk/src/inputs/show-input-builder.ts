import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha2";
import { Field } from "@noble/curves/abstract/modular";

import { base64urlToBigInt } from "../utils.js";
import { InputError } from "../errors.js";
import { buildShowStatementFields } from "./show-statement.js";
import type {
  ShowCircuitParams,
  ShowCircuitInputs,
  EcdsaPublicKey,
  EcdsaPrivateKey,
} from "../types.js";

const Fq = Field(
  BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
);

export function signDeviceNonce(
  nonce: string,
  privateKey: EcdsaPrivateKey,
): string {
  const privateKeyBytes =
    typeof privateKey === "string" ? hexToBytes(privateKey) : privateKey;

  const messageHash = sha256(new TextEncoder().encode(nonce));
  const signature = p256.sign(messageHash, privateKeyBytes, { lowS: true });

  return bytesToBase64url(signature.toCompactRawBytes());
}

/** Predicate operator codes matching eval-predicate.circom */
export const PredicateOp = {
  LE: 0,
  GE: 1,
  EQ: 2,
} as const;

/** Logic token types for postfix expression evaluation */
export const LogicToken = {
  REF: 0,
  AND: 1,
  OR: 2,
  NOT: 3,
} as const;

export type PredicateRhs =
  | { kind: "literal"; value: bigint }
  | { kind: "claimRef"; index: number; name: string };

export interface PredicateSpec {
  claimRef: number;
  /** Attribute name of the LHS claim; the circuit hashes it to the bound identity. */
  claimName: string;
  op: number;
  rhs: PredicateRhs;
}

export interface ShowInputOptions {
  /** Normalized claim values (from JWT circuit output). */
  normalizedClaimValues?: bigint[];
  /**
   * Per-slot attribute identities H(name), read from the Prepare (JWT) witness.
   * Must equal what the credential circuit derived so comm_W_shared matches.
   * The SDK never computes these (no off-circuit hashing).
   */
  claimIdentifierHashes?: bigint[];
  /** Predicate specifications. Defaults to a single EQ predicate on claim 0. */
  predicates?: PredicateSpec[];
  /** Postfix logic expression as [tokenType, tokenValue] pairs. Defaults to REF(0). */
  logicExpression?: Array<{ type: number; value: number }>;
}

export function buildShowCircuitInputs(
  params: ShowCircuitParams,
  nonce: string,
  deviceSignature: string,
  deviceKey: EcdsaPublicKey,
  options: ShowInputOptions = {},
): ShowCircuitInputs {
  const sigBytes = base64Decode(deviceSignature);
  const sigHex = Array.from(sigBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const sigParsed = p256.Signature.fromCompact(sigHex);
  // Hardware signers emit either S; the profile requires low-S, so flip
  // s := n - s (still a valid signature for the same message) rather than reject.
  const sigDecoded = sigParsed.hasHighS() ? sigParsed.normalizeS() : sigParsed;
  const sigSInverse = Fq.inv(sigDecoded.s);

  if (deviceKey.kty !== "EC" || deviceKey.crv !== "P-256") {
    throw new InputError("INVALID_KEY", "Device key must be P-256 EC key");
  }
  const deviceKeyX = base64urlToBigInt(deviceKey.x);
  const deviceKeyY = base64urlToBigInt(deviceKey.y);

  const pubkey = p256.ProjectivePoint.fromAffine({
    x: deviceKeyX,
    y: deviceKeyY,
  });
  try {
    pubkey.assertValidity();
  } catch {
    throw new InputError(
      "INVALID_KEY",
      "Device key is not a valid P-256 curve point",
    );
  }
  const msgHash = sha256(new TextEncoder().encode(nonce));
  const sigForVerify = sigDecoded.toDERRawBytes();
  const isValid = p256.verify(sigForVerify, msgHash, pubkey.toRawBytes());
  if (!isValid) {
    throw new InputError(
      "INVALID_SIGNATURE",
      "Device signature verification failed",
    );
  }

  const normalizedValues = options.normalizedClaimValues ?? [0n];
  const claimValues: bigint[] = Array(params.nClaims).fill(0n);
  for (let i = 0; i < Math.min(params.nClaims, normalizedValues.length); i++) {
    claimValues[i] = normalizedValues[i]!;
  }

  const predicates = options.predicates ?? [
    {
      claimRef: 0,
      claimName: "",
      op: PredicateOp.EQ,
      rhs: { kind: "literal", value: claimValues[0]! },
    },
  ];

  // Per-slot identities come from the Prepare witness (never computed here).
  const claimIdentifierHashes: bigint[] = Array(params.nClaims).fill(0n);
  const identities = options.claimIdentifierHashes ?? [];
  for (let i = 0; i < Math.min(params.nClaims, identities.length); i++) {
    claimIdentifierHashes[i] = identities[i]!;
  }
  const logicExpr = options.logicExpression ?? [
    { type: LogicToken.REF, value: 0 },
  ];

  // Build the verifier statement (messageHash + padded predicate program) via
  // the shared helper so the prover and verifier compute byte-identical public
  // values.
  const statement = buildShowStatementFields(
    params,
    nonce,
    predicates,
    logicExpr,
  );

  return {
    deviceKeyX,
    deviceKeyY,
    sig_r: sigDecoded.r,
    sig_s_inverse: sigSInverse,
    messageHash: statement.messageHash,
    predicateLen: statement.predicateLen,
    claimValues,
    claimIdentifierHashes,
    predicateClaimRefs: statement.predicateClaimRefs,
    predicateOps: statement.predicateOps,
    predicateRhsIsRef: statement.predicateRhsIsRef,
    predicateRhsValues: statement.predicateRhsValues,
    predicateClaimNames: statement.predicateClaimNames,
    predicateClaimNameLens: statement.predicateClaimNameLens,
    predicateRhsClaimNames: statement.predicateRhsClaimNames,
    predicateRhsClaimNameLens: statement.predicateRhsClaimNameLens,
    tokenTypes: statement.tokenTypes,
    tokenValues: statement.tokenValues,
    exprLen: statement.exprLen,
  };
}

function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function base64Decode(input: string): Uint8Array {
  let b64 = input.replace(/-/g, "+").replace(/_/g, "/");
  const pad = (4 - (b64.length % 4)) % 4;
  b64 += "=".repeat(pad);

  const binStr = atob(b64);
  const bytes = new Uint8Array(binStr.length);
  for (let i = 0; i < binStr.length; i++) {
    bytes[i] = binStr.charCodeAt(i);
  }
  return bytes;
}

function bytesToBase64url(bytes: Uint8Array): string {
  const B64_CHARS =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let result = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i]!;
    const b = bytes[i + 1] ?? 0;
    const c = bytes[i + 2] ?? 0;
    const triplet = (a << 16) | (b << 8) | c;
    result += B64_CHARS[(triplet >> 18) & 0x3f];
    result += B64_CHARS[(triplet >> 12) & 0x3f];
    result += i + 1 < bytes.length ? B64_CHARS[(triplet >> 6) & 0x3f]! : "";
    result += i + 2 < bytes.length ? B64_CHARS[triplet & 0x3f]! : "";
  }
  return result.replace(/\+/g, "-").replace(/\//g, "_");
}
