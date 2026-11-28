import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2";
import { Field } from "@noble/curves/abstract/modular";

import {
  base64Decode,
  uint8ArrayToBigIntArray,
  stringToPaddedBigIntArray,
  sha256Pad,
  encodeClaims,
  utf8Decode,
  utf8Encode,
} from "../utils.js";
import { InputError } from "../errors.js";
import { Credential } from "../credential.js";
import { issuerPublicKeyToPoint } from "./issuer-key.js";
import {
  assertUnambiguousPayload,
  DEVICE_KEY_ANCHORS,
  REVOCATION_VALUE_ANCHOR,
} from "./payload-anchors.js";
import type {
  JwtCircuitParams,
  JwtCircuitInputs,
  IssuerPublicKey,
} from "../types.js";

const Fq = Field(
  BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
);

export function buildJwtCircuitInputs(
  credential: Credential,
  issuerPublicKey: IssuerPublicKey,
  params: JwtCircuitParams,
  additionalMatches: string[],
  decodeFlags: number[],
  claimFormats: number[] = [],
): JwtCircuitInputs {
  const { b64Header, b64Payload, b64Signature } = credential;

  if (b64Payload.length > params.maxB64PayloadLength) {
    throw new InputError(
      "PARAMS_EXCEEDED",
      `Payload length (${b64Payload.length}) exceeds maxB64PayloadLength (${params.maxB64PayloadLength})`,
    );
  }

  const signingInput = `${b64Header}.${b64Payload}`;

  if (signingInput.length > params.maxMessageLength) {
    throw new InputError(
      "PARAMS_EXCEEDED",
      `Message length (${signingInput.length}) exceeds maxMessageLength (${params.maxMessageLength})`,
    );
  }

  // decode signature
  const sigBytes = base64Decode(b64Signature);
  const sigHex = Array.from(sigBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const sigDecoded = p256.Signature.fromCompact(sigHex);
  const sigSInverse = Fq.inv(sigDecoded.s);

  // Decode the issuer public key. These coordinates are private inputs: they
  // reach Show only through comm_W_shared, where issuer hiding proves the key
  // is in the issuer registry without revealing it.
  const { x: pubKeyX, y: pubKeyY } = issuerPublicKeyToPoint(issuerPublicKey);

  // verify signature off-chain
  const pubkey = p256.ProjectivePoint.fromAffine({ x: pubKeyX, y: pubKeyY });
  const sigForVerify = sigDecoded.toDERRawBytes();
  const check = p256.verify(
    sigForVerify,
    sha256(signingInput),
    pubkey.toRawBytes(),
  );
  if (!check) {
    throw new InputError(
      "INVALID_SIGNATURE",
      "JWT signature verification failed",
    );
  }

  // SHA-256 pad the message
  const messageBytes = utf8Encode(signingInput);
  const [messagePadded, messagePaddedLen] = sha256Pad(
    messageBytes,
    params.maxMessageLength,
  );

  // payload matching
  const decodedPayload = utf8Decode(base64Decode(b64Payload));

  // The circuit matches these patterns anywhere in the payload, so it can only
  // extract the intended values when each pattern has a single possible
  // position. Reject the payload otherwise.
  assertUnambiguousPayload(credential, decodedPayload, additionalMatches);

  // first two patterns are always "x":" and "y":" for device key extraction
  const patterns = [...DEVICE_KEY_ANCHORS, ...additionalMatches];

  if (patterns.length > params.maxMatches) {
    throw new InputError(
      "PARAMS_EXCEEDED",
      `Total patterns (${patterns.length}) exceeds maxMatches (${params.maxMatches})`,
    );
  }

  const matchSubstring: bigint[][] = [];
  const matchLength: number[] = [];
  const matchIndex: number[] = [];

  for (const pattern of patterns) {
    if (pattern.length > params.maxSubstringLength) {
      throw new InputError(
        "PARAMS_EXCEEDED",
        `Pattern "${pattern}" length exceeds maxSubstringLength (${params.maxSubstringLength})`,
      );
    }

    const index = decodedPayload.indexOf(pattern);
    if (index === -1) {
      throw new InputError(
        "CLAIM_NOT_FOUND",
        `Pattern "${pattern}" not found in JWT payload`,
      );
    }

    matchSubstring.push(
      stringToPaddedBigIntArray(pattern, params.maxSubstringLength),
    );
    matchLength.push(pattern.length);
    matchIndex.push(byteOffset(decodedPayload, index));
  }

  // pad remaining match slots
  while (matchSubstring.length < params.maxMatches) {
    matchSubstring.push(
      stringToPaddedBigIntArray("", params.maxSubstringLength),
    );
    matchLength.push(0);
    matchIndex.push(0);
  }

  // claims processing: claim-only slots (maxClaims = maxMatches - 2)
  const maxClaims = params.maxMatches - 2;
  const rawDisclosures = credential.claims.map((c) => c.raw);
  const { claimArray, claimLengths } = encodeClaims(
    rawDisclosures,
    maxClaims,
    params.maxClaimLength,
  );

  // align decode flags to claim-only slots
  const decodeFlagsOut: number[] = [];
  for (let i = 0; i < maxClaims; i++) {
    decodeFlagsOut.push(i < decodeFlags.length ? decodeFlags[i]! : 0);
  }

  // Build claimFormats array for claim-only slots
  // Default: uint (1) for unspecified formats
  const claimFormatsOut: bigint[] = [];
  for (let i = 0; i < maxClaims; i++) {
    claimFormatsOut.push(BigInt(i < claimFormats.length ? claimFormats[i]! : 1));
  }

  return {
    sig_r: sigDecoded.r,
    sig_s_inverse: sigSInverse,
    pubKeyX,
    pubKeyY,
    message: uint8ArrayToBigIntArray(messagePadded),
    messageLength: messagePaddedLen,
    periodIndex: credential.token.indexOf("."),
    matchesCount: patterns.length,
    matchSubstring,
    matchLength,
    matchIndex,
    claims: claimArray,
    claimLengths,
    decodeFlags: decodeFlagsOut,
    claimFormats: claimFormatsOut,
    revocationValueIndex: byteOffset(
      decodedPayload,
      decodedPayload.indexOf(REVOCATION_VALUE_ANCHOR),
    ),
  };
}

// The circuit indexes payload bytes; String.indexOf counts UTF-16 code units.
function byteOffset(text: string, index: number): number {
  return utf8Encode(text.slice(0, index)).length;
}
