import crypto from "crypto";
import "reflect-metadata";
import * as x509 from "@peculiar/x509";
import { ISO_NAMESPACE, MDL_DOCTYPE, type ParsedIssuerSignedItem } from "./mdoc.ts";

// @auth0/mdl and cbor have no usable TS types — use require to avoid `as any` casts.
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { Document, MDoc, parse: parseMdoc } = require("@auth0/mdl");
// eslint-disable-next-line @typescript-eslint/no-require-imports
const cbor = require("cbor");

export interface TestMdocCredential {
  tbsData: Uint8Array;
  signature: Uint8Array;
  issuerPubRaw: Uint8Array;
  deviceKeyX: Uint8Array;
  deviceKeyY: Uint8Array;
  devPrvJwk: JsonWebKey;
  devPrvHex: string;
  devPubJwk: JsonWebKey;
  items: ParsedIssuerSignedItem[];
  claims: Record<string, string>;
}

const DEFAULT_CLAIMS: Record<string, string> = {
  family_name: "Smith",
  given_name: "Alice",
  birth_date: "1990-07-15",
  resident_state: "CA",
};

const DEFAULT_VALIDITY = {
  signed: new Date("2025-01-01T00:00:00Z"),
  validFrom: new Date("2025-01-01T00:00:00Z"),
  validUntil: new Date("2027-12-31T00:00:00Z"),
};

const ECDSA_P256: EcKeyGenParams = { name: "ECDSA", namedCurve: "P-256" };

async function generateP256KeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(ECDSA_P256, true, ["sign", "verify"]);
}

async function generateIssuerMaterial() {
  const keys = await generateP256KeyPair();
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: "CN=TestIssuer",
    notBefore: new Date(),
    notAfter: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    keys,
  });
  const privateJwk = await crypto.subtle.exportKey("jwk", keys.privateKey);
  const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
  return {
    privateJwk: { ...privateJwk, alg: "ES256" },
    publicRaw,
    certDer: Buffer.from(cert.rawData),
  };
}

async function generateDeviceKey() {
  const keys = await generateP256KeyPair();
  const pubJwk = await crypto.subtle.exportKey("jwk", keys.publicKey);
  const prvJwk = await crypto.subtle.exportKey("jwk", keys.privateKey);
  return {
    pubJwk,
    prvJwk,
    prvHex: Buffer.from(prvJwk.d!, "base64url").toString("hex"),
  };
}

function extractIssuerSignedItem(item: any): ParsedIssuerSignedItem {
  const innerBytes: Buffer = Buffer.from(item.encode());
  const preimage = Buffer.from(cbor.encode(new cbor.Tagged(24, innerBytes)));

  const idCbor = Buffer.from(cbor.encode(item.elementIdentifier));
  const identifierCborPos = preimage.indexOf(idCbor);
  if (identifierCborPos < 0) {
    throw new Error(`identifier CBOR not found for "${item.elementIdentifier}"`);
  }

  const elementValueLabel = Buffer.concat([Buffer.from([0x6c]), Buffer.from("elementValue")]);
  const elementValueLabelPos = preimage.indexOf(elementValueLabel);
  if (elementValueLabelPos < 0) {
    throw new Error(`elementValue label not found for "${item.elementIdentifier}"`);
  }

  // @auth0/mdl decodes Tag 1004 as Date; re-serialize to "YYYY-MM-DD" to find it in the CBOR.
  const valueStr =
    item.elementValue instanceof Date ? item.elementValue.toISOString().slice(0, 10) : String(item.elementValue);
  const valueBytes = Buffer.from(valueStr, "utf-8");
  const valueStart = preimage.indexOf(valueBytes);
  if (valueStart < 0) {
    throw new Error(
      `value bytes not found in preimage for "${item.elementIdentifier}" ` +
        `(value=${JSON.stringify(item.elementValue)})`,
    );
  }

  return {
    identifier: item.elementIdentifier,
    digestId: item.digestID,
    preimage: new Uint8Array(preimage),
    identifierCborPos,
    elementValueLabelPos,
    valueStart,
    valueEnd: valueStart + valueBytes.length,
  };
}

/** Build a real mDL credential and the byte offsets the MDOC circuit needs. */
export async function createTestMdocCredential(
  claims: Record<string, string> = DEFAULT_CLAIMS,
): Promise<TestMdocCredential> {
  const issuer = await generateIssuerMaterial();
  const device = await generateDeviceKey();

  const signed = await new Document(MDL_DOCTYPE)
    .addIssuerNameSpace(ISO_NAMESPACE, claims)
    .useDigestAlgorithm("SHA-256")
    .addValidityInfo(DEFAULT_VALIDITY)
    .addDeviceKeyInfo({ deviceKey: device.pubJwk })
    .sign({
      issuerPrivateKey: issuer.privateJwk,
      issuerCertificate: issuer.certDer,
      alg: "ES256",
    });

  const mdocBytes = Buffer.from(new MDoc([signed]).encode());
  const doc = parseMdoc(mdocBytes).documents[0];
  const ia = doc.issuerSigned.issuerAuth;

  // COSE_Sign1 TBS: ["Signature1", protected, external_aad, payload]
  const tbsData: Buffer = cbor.encode([
    "Signature1",
    Buffer.from(ia.encodedProtectedHeaders),
    Buffer.alloc(0),
    Buffer.from(ia.payload),
  ]);

  const deviceKeyMap = ia.decodedPayload.deviceKeyInfo.deviceKey;
  const items: ParsedIssuerSignedItem[] = doc.issuerSigned.nameSpaces[ISO_NAMESPACE].map(extractIssuerSignedItem);

  return {
    tbsData: new Uint8Array(tbsData),
    signature: new Uint8Array(ia.signature),
    issuerPubRaw: issuer.publicRaw,
    deviceKeyX: new Uint8Array(deviceKeyMap.get(-2)),
    deviceKeyY: new Uint8Array(deviceKeyMap.get(-3)),
    devPrvJwk: device.prvJwk,
    devPrvHex: device.prvHex,
    devPubJwk: device.pubJwk,
    items,
    claims,
  };
}
