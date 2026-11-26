import { describe, expect, it } from "vitest";
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2";
import { Credential } from "../src/credential.js";
import { buildJwtCircuitInputs } from "../src/inputs/jwt-input-builder.js";
import { JWT_PARAMS_BY_SIZE, selectVcSizeForSigningInput } from "../src/sizing.js";
import { base64urlEncode, bigintToBytes } from "../src/utils.js";

const ISSUER_PRIV = bigintToBytes(
  0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef1n,
  32,
);
const ISSUER_PUB_POINT = p256.ProjectivePoint.fromPrivateKey(ISSUER_PRIV).toAffine();
const ISSUER_PUBLIC_KEY = {
  kty: "EC" as const,
  crv: "P-256" as const,
  x: base64urlEncode(bigintToBytes(ISSUER_PUB_POINT.x, 32)),
  y: base64urlEncode(bigintToBytes(ISSUER_PUB_POINT.y, 32)),
};

function buildSignedSdJwt(
  headerObj: Record<string, unknown>,
  targetB64PayloadLength: number,
) {
  const disclosure = base64urlEncode(
    new TextEncoder().encode(JSON.stringify(["long-salt-for-two-block-padding-fixture", "age", "25"])),
  );
  const digest = base64urlEncode(sha256(new TextEncoder().encode(disclosure)));

  const basePayload = (pad: string) => ({
    sub: "did:key:test",
    iss: "did:key:issuer",
    cnf: {
      jwk: {
        kty: "EC" as const,
        crv: "P-256" as const,
        x: ISSUER_PUBLIC_KEY.x,
        y: ISSUER_PUBLIC_KEY.y,
      },
    },
    vc: {
      credentialSubject: {
        _sd: [digest],
        _sd_alg: "sha-256",
        pad,
      },
    },
  });

  const emptyLen = JSON.stringify(basePayload("")).length;
  const rawPayloadLen = Math.floor((targetB64PayloadLength * 3) / 4);
  const payloadObj = basePayload("a".repeat(rawPayloadLen - emptyLen));
  const b64Header = base64urlEncode(new TextEncoder().encode(JSON.stringify(headerObj)));
  const b64Payload = base64urlEncode(new TextEncoder().encode(JSON.stringify(payloadObj)));
  expect(b64Payload.length).toBe(targetB64PayloadLength);

  const signingInput = `${b64Header}.${b64Payload}`;
  const sig = p256.sign(sha256(signingInput), ISSUER_PRIV);
  const jwt = `${signingInput}.${base64urlEncode(sig.toCompactRawBytes())}`;
  const credential = Credential.parse(jwt, [disclosure]);

  return { credential, signingLength: signingInput.length, b64PayloadLength: b64Payload.length };
}

describe("SDK profile selection vs maxB64PayloadLength", () => {
  const standardHeader = { alg: "ES256", typ: "vc+sd-jwt" };

  it("builds inputs when b64PayloadLength fits within 1k's 960-char limit", () => {
    const { credential, signingLength, b64PayloadLength } = buildSignedSdJwt(standardHeader, 960);
    expect(b64PayloadLength).toBe(960);
    expect(signingLength).toBeLessThanOrEqual(1271);

    const selected = selectVcSizeForSigningInput(signingLength);
    expect(selected).toBe("1k");
    expect(() =>
      buildJwtCircuitInputs(
        credential,
        ISSUER_PUBLIC_KEY,
        JWT_PARAMS_BY_SIZE[selected],
        credential.disclosureHashes,
        [1, 0],
        [1, 1],
      ),
    ).not.toThrow();
  });

  it.each([
    { label: "1k at b64PayloadLength = 964 (exceeds SDK 960 cap)", header: standardHeader, payloadLen: 964 },
    { label: "1k at b64PayloadLength = 1026 (exceeds both 960 cap and circuit 1024 bound)", header: standardHeader, payloadLen: 1026 },
    { label: "4k at b64PayloadLength = 4002 with minimal 20-byte header (4023 signing bytes)", header: { alg: "ES256" }, payloadLen: 4002 },
  ])("selects a profile whose maxB64PayloadLength accepts $label", ({ header, payloadLen }) => {
    const { credential, signingLength } = buildSignedSdJwt(header, payloadLen);
    const selected = selectVcSizeForSigningInput(signingLength);

    expect(() =>
      buildJwtCircuitInputs(
        credential,
        ISSUER_PUBLIC_KEY,
        JWT_PARAMS_BY_SIZE[selected],
        credential.disclosureHashes,
        [1, 0],
        [1, 1],
      ),
    ).not.toThrow();
  });
});
