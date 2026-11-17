import { describe, it, expect } from "vitest";
import { sha256 } from "@noble/hashes/sha2";

import { Credential } from "../src/credential.js";
import { assertUnambiguousPayload } from "../src/inputs/payload-anchors.js";
import { buildJwtCircuitInputs } from "../src/inputs/jwt-input-builder.js";
import { JWT_PARAMS_BY_SIZE } from "../src/sizing.js";
import { generateDummyCredential } from "../src/testing/dummy-credential.js";
import { base64urlEncode } from "../src/utils.js";
import { encodeRevocationCommitment } from "../src/revocation.js";

const REVOCATION_COMMITMENT = encodeRevocationCommitment(123456789n);

const DEVICE_JWK = {
  kty: "EC" as const,
  crv: "P-256" as const,
  x: "dGVzdC14LWNvb3JkaW5hdGUtZm9yLXAyNTYtY3VydmU",
  y: "dGVzdC15LWNvb3JkaW5hdGUtZm9yLXAyNTYtY3VydmU",
};

function disclosure(salt: string, name: string, value: string): string {
  return base64urlEncode(
    new TextEncoder().encode(JSON.stringify([salt, name, value])),
  );
}

function digestOf(raw: string): string {
  return base64urlEncode(sha256(new TextEncoder().encode(raw)));
}

// The signature is never checked on this path, so an unsigned token is enough to
// exercise the anchor rules over an arbitrary payload shape.
function credentialWith(
  payloadExtras: Record<string, unknown>,
  sd: string[],
  disclosures: string[],
): Credential {
  const header = { alg: "ES256", typ: "vc+sd-jwt" };
  const payload = {
    iss: "did:key:issuer",
    revocation_commitment: REVOCATION_COMMITMENT,
    ...payloadExtras,
    cnf: { jwk: DEVICE_JWK },
    vc: { credentialSubject: { _sd: sd, _sd_alg: "sha-256" } },
  };
  const encode = (o: unknown) =>
    base64urlEncode(new TextEncoder().encode(JSON.stringify(o)));
  const jwt = `${encode(header)}.${encode(payload)}.${base64urlEncode(
    new Uint8Array(64),
  )}`;
  return Credential.parse(jwt, disclosures);
}

describe("assertUnambiguousPayload", () => {
  const raw = disclosure("salt1", "age", "42");
  const digest = digestOf(raw);

  it("accepts a payload where every anchor has a single position", () => {
    const cred = credentialWith({}, [digest], [raw]);
    expect(() =>
      assertUnambiguousPayload(cred, cred.decodedPayload, [digest]),
    ).not.toThrow();
  });

  it("rejects a second x/y pair that could be read as the device key", () => {
    const cred = credentialWith(
      { point: { x: "YXR0YWNrZXI", y: "YXR0YWNrZXI" } },
      [digest],
      [raw],
    );
    expect(() =>
      assertUnambiguousPayload(cred, cred.decodedPayload, [digest]),
    ).toThrow(/occurs 2 times/);
  });

  it("rejects a payload without a revocation commitment", () => {
    const cred = credentialWith({ revocation_commitment: undefined }, [digest], [raw]);
    expect(() =>
      assertUnambiguousPayload(cred, cred.decodedPayload, [digest]),
    ).toThrow(/revocation_commitment/);
  });

  it("rejects a second revocation commitment anchor", () => {
    const cred = credentialWith(
      { nested: { revocation_commitment: REVOCATION_COMMITMENT } },
      [digest],
      [raw],
    );
    expect(() =>
      assertUnambiguousPayload(cred, cred.decodedPayload, [digest]),
    ).toThrow(/must occur once/);
  });

  it("rejects a nested _sd array", () => {
    const cred = credentialWith({ nested: { _sd: [digest] } }, [digest], [raw]);
    expect(() =>
      assertUnambiguousPayload(cred, cred.decodedPayload, [digest]),
    ).toThrow(/_sd/);
  });

  it("rejects a digest that appears only outside the _sd array", () => {
    const other = disclosure("salt2", "name", "John");
    const otherDigest = digestOf(other);
    const cred = credentialWith({ reference: otherDigest }, [digest], [
      raw,
      other,
    ]);
    expect(() =>
      assertUnambiguousPayload(cred, cred.decodedPayload, [
        digest,
        otherDigest,
      ]),
    ).toThrow(/not an element of the credential's _sd array/);
  });

  it("rejects a digest that occurs both inside and outside _sd", () => {
    const cred = credentialWith({ reference: digest }, [digest], [raw]);
    expect(() =>
      assertUnambiguousPayload(cred, cred.decodedPayload, [digest]),
    ).toThrow(/occurs 2 times/);
  });
});

describe("buildJwtCircuitInputs anchor enforcement", () => {
  it("accepts a well formed dummy credential", () => {
    const data = generateDummyCredential({ size: "1k" });
    const cred = Credential.parse(data.jwt, data.disclosures);
    expect(() =>
      buildJwtCircuitInputs(
        cred,
        data.issuerPublicKey,
        JWT_PARAMS_BY_SIZE["1k"],
        cred.disclosureHashes,
        [],
        [],
      ),
    ).not.toThrow();
  });
});
