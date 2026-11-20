import * as nodeCrypto from "crypto";
import * as jwt from "jsonwebtoken";
import jwkToPem from "jwk-to-pem";
import * as fs from "fs";
import * as path from "path";
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2";
import type { JwkEcdsaPublicKey } from "./es256.ts";
import { generateJwtCircuitParams, generateJwtInputs } from "./jwt.ts";
import type { JwtCircuitParams } from "./jwt.ts";
import { base64ToBigInt, base64urlToBase64, bigintToBase64url, pointToJwk, generateDidKey } from "./utils.ts";

interface PublicKeyConfig {
  kty: string;
  crv: string;
  kid: string;
  x: string;
  y: string;
}

interface PublicKeysConfig {
  keys: PublicKeyConfig[];
}

const PRIVATE_KEYS: Record<string, string> = {
  "key-1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "key-2": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
  "key-3": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
};

let publicKeysConfigCache: PublicKeysConfig | null = null;
const DEFAULT_KEYS_URL =
  "https://raw.githubusercontent.com/privacy-ethereum/zkID/refs/heads/main/wallet-unit-poc/circom/keys.json";
const LOCAL_KEYS_PATH = path.join(__dirname, "..", "keys.json");

function loadPublicKeysConfig(): PublicKeysConfig {
  const fileContent = fs.readFileSync(LOCAL_KEYS_PATH, "utf8");
  const publicKeysConfig: PublicKeysConfig = JSON.parse(fileContent);
  return publicKeysConfig;
}

async function getIssuerKey(
  kid: string,
): Promise<{ privateKey: Buffer; publicKey: JwkEcdsaPublicKey; kid: string; jku: string }> {
  const publicKeysConfig = loadPublicKeysConfig();
  const publicKeyConfig = publicKeysConfig.keys.find((k) => k.kid === kid) || publicKeysConfig.keys[0];
  const privateKeyHex = PRIVATE_KEYS[publicKeyConfig.kid] || PRIVATE_KEYS["key-1"];
  const privateKey = Buffer.from(privateKeyHex, "hex");

  const publicKey: JwkEcdsaPublicKey = {
    kty: publicKeyConfig.kty as "EC",
    crv: publicKeyConfig.crv as "P-256",
    x: publicKeyConfig.x,
    y: publicKeyConfig.y,
  };

  return { privateKey, publicKey, kid: publicKeyConfig.kid, jku: DEFAULT_KEYS_URL };
}

function generateSalt(): string {
  return nodeCrypto.randomBytes(16).toString("base64url");
}

function generateDeviceBindingKey(): { privateKey: Uint8Array; publicKey: JwkEcdsaPublicKey } {
  const privateKey = p256.utils.randomPrivateKey();
  const point = p256.ProjectivePoint.fromPrivateKey(privateKey);
  const publicKey = pointToJwk({ x: point.x, y: point.y }) as JwkEcdsaPublicKey;
  return { privateKey, publicKey };
}

function signJWT(header: any, payload: any, privateKeyJwk: any): string {
  const pemPrivateKey = jwkToPem(privateKeyJwk, { private: true });
  return jwt.sign(payload, pemPrivateKey, { algorithm: "ES256", header });
}

export function verifyJWTSignature(token: string, publicKey: JwkEcdsaPublicKey): boolean {
  const [b64Header, b64Payload, b64Signature] = token.split(".");
  const message = `${b64Header}.${b64Payload}`;
  const sig = Buffer.from(b64Signature, "base64url");
  const sigDecoded = p256.Signature.fromCompact(sig.toString("hex"));
  const x = base64ToBigInt(base64urlToBase64(publicKey.x));
  const y = base64ToBigInt(base64urlToBase64(publicKey.y));
  const pubkey = new p256.Point(x, y, 1n);
  const sigDER = sigDecoded.toDERRawBytes();
  const messageHash = sha256(message);
  return p256.verify(sigDER, messageHash, pubkey.toRawBytes());
}

function generateClaim(key: string, value: string): string {
  const salt = generateSalt();
  const claim = JSON.stringify([salt, key, value]);
  return Buffer.from(claim).toString("base64url");
}

export interface MockDataOptions {
  claims?: Array<{ key: string; value: string }>;
  circuitParams?: number[];
  subject?: string;
  issuer?: string;
  matches?: string[];
  kid?: string;
  targetPayloadLength?: number;
  claimFormats?: number[];
  /** Extra top-level fields merged into the signed payload (tests only). */
  extraPayload?: Record<string, unknown>;
}

export interface MockDataResult {
  tokenWithClaims: string;
  token: string;
  claims: string[];
  hashedClaims: string[];
  issuerKey: JwkEcdsaPublicKey;
  deviceKey: JwkEcdsaPublicKey;
  devicePrivateKey: Uint8Array;
  circuitParams: JwtCircuitParams;
  circuitInputs: any;
}

export async function generateMockData(options: MockDataOptions = {}): Promise<MockDataResult> {
  const defaultClaims = [
    { key: "name", value: "John Doe" },
    { key: "roc_birthday", value: "1040605" },
  ];
  const claims = options.claims || defaultClaims;
  const kid = options.kid || "key-1";
  const issuerKeyData = await getIssuerKey(kid);
  const { privateKey: devicePrivateKey, publicKey: deviceKey } = generateDeviceBindingKey();

  const privateKeyHex = Buffer.from(issuerKeyData.privateKey).toString("hex");
  const issuerJwkPrivate = {
    ...issuerKeyData.publicKey,
    d: bigintToBase64url(BigInt("0x" + privateKeyHex)),
  };

  const claimStrings = claims.map((claim) => generateClaim(claim.key, claim.value));

  const hashedClaims = claimStrings.map((claim) => {
    const claimBytes = Uint8Array.from(Buffer.from(claim, "utf8"));
    return Buffer.from(sha256(claimBytes)).toString("base64url");
  });

  const header = {
    jku: issuerKeyData.jku,
    kid: issuerKeyData.kid,
    typ: "vc+sd-jwt",
    alg: "ES256",
  };

  const issuerDid = options.issuer || generateDidKey(issuerKeyData.publicKey);
  const subjectDid = options.subject || generateDidKey(deviceKey);

  const payload = {
    sub: subjectDid,
    nbf: Math.floor(Date.now() / 1000),
    iss: issuerDid,
    cnf: { jwk: deviceKey },
    exp: Math.floor(Date.now() / 1000) + 3600,
    vc: {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      type: ["VerifiableCredential", "MockCredential"],
      credentialSubject: {
        _sd: hashedClaims,
        _sd_alg: "sha-256",
      },
    },
    nonce: nodeCrypto.randomBytes(16).toString("base64url"),
    ...options.extraPayload,
  };

  if (options.targetPayloadLength) {
    const targetLen = options.targetPayloadLength;
    const probeToken = signJWT(header, { ...payload }, issuerJwkPrivate);
    const probePayloadLen = probeToken.split(".")[1].length;

    let effectiveTarget = targetLen;
    if (options.circuitParams) {
      const maxMessageLength = options.circuitParams[0];
      const headerLen = probeToken.split(".")[0].length;
      const sigLen = probeToken.split(".")[2].length;
      const overhead = headerLen + 2 + sigLen; // 2 dots
      const maxPayloadFromMsg = maxMessageLength - overhead;
      effectiveTarget = Math.min(targetLen, maxPayloadFromMsg);
    }

    if (probePayloadLen < effectiveTarget) {
      let lo = 0;
      let hi = Math.ceil((effectiveTarget - probePayloadLen) * 2) + 100;
      while (lo < hi) {
        const mid = Math.floor((lo + hi + 1) / 2);
        const testToken = signJWT(header, { ...payload, _padding: "A".repeat(mid) }, issuerJwkPrivate);
        const testLen = testToken.split(".")[1].length;
        if (testLen <= effectiveTarget) {
          lo = mid;
        } else {
          hi = mid - 1;
        }
      }
      if (lo > 0) {
        (payload as any)._padding = "A".repeat(lo);
      }
    }
  }

  const token = signJWT(header, payload, issuerJwkPrivate);
  const tokenWithClaims = [token, ...claimStrings].join("~");
  const [, b64payload] = token.split(".");
  const actualPayloadLength = b64payload.length;

  let circuitParamsArray: number[];
  if (options.circuitParams) {
    circuitParamsArray = options.circuitParams;
    if (circuitParamsArray[1] < actualPayloadLength) {
      throw new Error(
        `maxB64PayloadLength (${circuitParamsArray[1]}) too small. Increase to at least ${actualPayloadLength + 100}.`,
      );
    }
    const minMatches = claims.length + 2;
    if (circuitParamsArray[2] < minMatches) {
      throw new Error(`maxMatches (${circuitParamsArray[2]}) too small. Must be at least ${minMatches}.`);
    }
  } else {
    const maxB64PayloadLength = Math.max(3000, actualPayloadLength + 200);
    const maxMatches = Math.max(6, claims.length + 4);
    circuitParamsArray = [2048, maxB64PayloadLength, maxMatches, 50, 128];
  }

  const circuitParams = generateJwtCircuitParams(circuitParamsArray);
  if (actualPayloadLength > circuitParams.maxB64PayloadLength) {
    throw new Error(
      `Payload length (${actualPayloadLength}) exceeds maxB64PayloadLength (${circuitParams.maxB64PayloadLength}).`,
    );
  }

  const matches = options.matches || hashedClaims;

  const circuitInputs = generateJwtInputs(
    circuitParams,
    token,
    issuerKeyData.publicKey,
    matches,
    claimStrings,
    options.claimFormats ?? [],
  );

  return {
    tokenWithClaims,
    token,
    claims: claimStrings,
    hashedClaims,
    issuerKey: issuerKeyData.publicKey,
    deviceKey,
    devicePrivateKey,
    circuitParams,
    circuitInputs,
  };
}
