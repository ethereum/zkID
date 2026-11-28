
import { describe, it, expect, beforeAll } from "vitest";
import { readFile } from "fs/promises";
import { existsSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2";

import {
  Credential,
  DEFAULT_SHOW_PARAMS,
  circuitInputsToJson,
  extractIssuerKeyFromPreparePublicValues,
  issuerPublicKeyToPoint,
  buildRevocationWitness,
  createRevocationRegistry,
  encodeRevocationValue,
} from "../src/index.js";
import { CLAIM_IDENTITY_WITNESS_START, CLAIM_VALUES_WITNESS_START } from "../src/sizing.js";
import { buildJwtCircuitInputs } from "../src/inputs/jwt-input-builder.js";
import {
  buildShowCircuitInputs,
  signDeviceNonce,
} from "../src/inputs/show-input-builder.js";
import type { JwtCircuitParams } from "../src/types.js";
import { WasmBridge } from "../src/wasm-bridge.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const KEYS_DIR = join(__dirname, "..", "..", "ecdsa-spartan2", "keys");
const WASM_PKG_DIR = join(__dirname, "..", "wasm", "pkg");
const ASSETS_DIR = join(__dirname, "..", "assets");

// The revocation value the issuer signs as `revocation_value`.
const REVOCATION_VALUE = 0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789n;

// 1k circuit params: must match circom/circuits.json "jwt_1k" params
const JWT_PARAMS_1K: JwtCircuitParams = {
  maxMessageLength: 1280,
  maxB64PayloadLength: 960,
  maxMatches: 4,
  maxSubstringLength: 50,
  maxClaimLength: 128,
};


function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
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

function jsonToBase64url(obj: unknown): string {
  const json = JSON.stringify(obj);
  return bytesToBase64url(new TextEncoder().encode(json));
}

function signES256(signingInput: string, privateKey: Uint8Array): string {
  const msgHash = sha256(signingInput);
  const sig = p256.sign(msgHash, privateKey);
  return bytesToBase64url(sig.toBytes("compact"));
}

function makeDisclosure(salt: string, key: string, value: string): string {
  const json = JSON.stringify([salt, key, value]);
  return bytesToBase64url(new TextEncoder().encode(json));
}

function disclosureDigest(disclosure: string): string {
  const hash = sha256(new TextEncoder().encode(disclosure));
  return bytesToBase64url(hash);
}

function derivePublicKey(privateKeyBytes: Uint8Array) {
  let hex = "";
  for (const b of privateKeyBytes) hex += b.toString(16).padStart(2, "0");
  return p256.ProjectivePoint.BASE.multiply(BigInt("0x" + hex));
}

/** Parse a WASM public value (Rust `{:?}` on a field element) into a bigint. */
function parseScalar(value: string): bigint {
  const hex = value.match(/0x([0-9a-fA-F]+)/);
  return hex ? BigInt("0x" + hex[1]) : BigInt(value.match(/-?\d+/)?.[0] ?? "0");
}

const ISSUER_PRIVATE_KEY_HEX =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const ISSUER_PRIVATE_KEY = hexToBytes(ISSUER_PRIVATE_KEY_HEX);
const ISSUER_POINT = derivePublicKey(ISSUER_PRIVATE_KEY);
const ISSUER_PUBLIC_KEY = {
  kty: "EC" as const,
  crv: "P-256" as const,
  x: bytesToBase64url(bigintToBytes(ISSUER_POINT.x, 32)),
  y: bytesToBase64url(bigintToBytes(ISSUER_POINT.y, 32)),
};

const DEVICE_PRIVATE_KEY_HEX =
  "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
const DEVICE_PRIVATE_KEY = hexToBytes(DEVICE_PRIVATE_KEY_HEX);
const DEVICE_POINT = derivePublicKey(DEVICE_PRIVATE_KEY);
const DEVICE_PUBLIC_KEY = {
  kty: "EC" as const,
  crv: "P-256" as const,
  x: bytesToBase64url(bigintToBytes(DEVICE_POINT.x, 32)),
  y: bytesToBase64url(bigintToBytes(DEVICE_POINT.y, 32)),
};

const VERIFIER_NONCE = "test-nonce-12345";

interface TestJwtData {
  jwt: string;
  disclosures: string[];
  claims: Array<{ salt: string; key: string; value: string }>;
  issuerPublicKey: { kty: "EC"; crv: "P-256"; x: string; y: string };
  devicePublicKey: { kty: "EC"; crv: "P-256"; x: string; y: string };
  devicePrivateKeyHex: string;
}

function generateTestJwt(): TestJwtData {
  const claimDefs = [
    { salt: "aGVsbG9fd29ybGRfMTIzNDU2", key: "name", value: "Alice" },
    {
      salt: "Z29vZGJ5ZV93b3JsZF83ODkwMTI",
      key: "roc_birthday",
      value: "0890615",
    },
  ];

  const disclosures = claimDefs.map((c) =>
    makeDisclosure(c.salt, c.key, c.value),
  );
  const hashedClaims = disclosures.map((d) => disclosureDigest(d));

  const header = { alg: "ES256", typ: "vc+sd-jwt" };
  const payload = {
    sub: "did:example:subject",
    iss: "did:example:issuer",
    nbf: 1700000000,
    exp: 1800000000,
    cnf: { jwk: DEVICE_PUBLIC_KEY },
    revocation_value: encodeRevocationValue(REVOCATION_VALUE),
    vc: {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      type: ["VerifiableCredential"],
      credentialSubject: {
        _sd: hashedClaims,
        _sd_alg: "sha-256",
      },
    },
    nonce: "fixed-test-nonce",
  };

  const b64Header = jsonToBase64url(header);
  const b64Payload = jsonToBase64url(payload);
  const signingInput = `${b64Header}.${b64Payload}`;
  const b64Signature = signES256(signingInput, ISSUER_PRIVATE_KEY);
  const jwt = `${signingInput}.${b64Signature}`;

  return {
    jwt,
    disclosures,
    claims: claimDefs,
    issuerPublicKey: ISSUER_PUBLIC_KEY,
    devicePublicKey: DEVICE_PUBLIC_KEY,
    devicePrivateKeyHex: DEVICE_PRIVATE_KEY_HEX,
  };
}


type CircuitInput = Record<string, unknown>;

interface WitnessCalculatorInstance {
  calculateWitness(
    input: CircuitInput,
    sanityCheck?: boolean,
  ): Promise<bigint[]>;
  calculateWTNSBin(
    input: CircuitInput,
    sanityCheck?: boolean,
  ): Promise<Uint8Array>;
}

type WitnessCalculatorBuilder = (
  code: ArrayBuffer | Uint8Array,
  options?: { sanityCheck?: boolean },
) => Promise<WitnessCalculatorInstance>;

async function createWitnessCalculator(
  wasmPath: string,
  builderPath: string,
): Promise<WitnessCalculatorInstance> {
  const module = await import(/* webpackIgnore: true */ builderPath);
  const builder: WitnessCalculatorBuilder = module.default ?? module;
  const wasmBuffer = await readFile(wasmPath);
  return await builder(wasmBuffer, { sanityCheck: true });
}

function checkArtifactsExist(): boolean {
  const requiredFiles = [
    join(KEYS_DIR, "1k_prepare_proving.key"),
    join(KEYS_DIR, "1k_prepare_verifying.key"),
    join(KEYS_DIR, "1k_show_proving.key"),
    join(KEYS_DIR, "1k_show_verifying.key"),
    join(WASM_PKG_DIR, "openac_wasm.js"),
    join(WASM_PKG_DIR, "openac_wasm_bg.wasm"),
    join(ASSETS_DIR, "jwt_1k.wasm"),
    join(ASSETS_DIR, "show.wasm"),
    join(__dirname, "..", "assets", "witness_calculator.js"),
  ];

  for (const file of requiredFiles) {
    if (!existsSync(file)) {
      return false;
    }
  }
  return true;
}

describe.skipIf(!checkArtifactsExist())(
  "Full Pipeline: 1k Circuit via WASM Bridge",
  () => {
  let bridge: WasmBridge;
  let wasmAvailable = false;
  let jwtWitnessCalc: WitnessCalculatorInstance;
  let showWitnessCalc: WitnessCalculatorInstance;
  let preparePk: Uint8Array;
  let prepareVk: Uint8Array;
  let showPk: Uint8Array;
  let showVk: Uint8Array;

  beforeAll(async () => {
    if (!checkArtifactsExist()) {
      return;
    }

    try {
      bridge = new WasmBridge();
      const wasmModule = await import(
        /* webpackIgnore: true */ join(WASM_PKG_DIR, "openac_wasm.js")
      );
      const wasmBinary = await readFile(
        join(WASM_PKG_DIR, "openac_wasm_bg.wasm"),
      );
      wasmModule.initSync({ module: wasmBinary });
      bridge.initWithModule(wasmModule);

      const [ppk, pvk, spk, svk] = await Promise.all([
        readFile(join(KEYS_DIR, "1k_prepare_proving.key")),
        readFile(join(KEYS_DIR, "1k_prepare_verifying.key")),
        readFile(join(KEYS_DIR, "1k_show_proving.key")),
        readFile(join(KEYS_DIR, "1k_show_verifying.key")),
      ]);
      preparePk = new Uint8Array(ppk);
      prepareVk = new Uint8Array(pvk);
      showPk = new Uint8Array(spk);
      showVk = new Uint8Array(svk);

      const witnessCalcJs = join(ASSETS_DIR, "witness_calculator.js");
      jwtWitnessCalc = await createWitnessCalculator(
        join(ASSETS_DIR, "jwt_1k.wasm"),
        witnessCalcJs,
      );
      showWitnessCalc = await createWitnessCalculator(
        join(ASSETS_DIR, "show.wasm"),
        witnessCalcJs,
      );

      wasmAvailable = true;
    } catch (error) {
      wasmAvailable = false;
    }
  }, 120_000);

  it("runs complete 1k pipeline: generate → precompute → present → verify", async () => {
    if (!wasmAvailable) {
      return;
    }

    const data = generateTestJwt();

    const credential = Credential.parse(data.jwt, data.disclosures);
    const birthdayIdx = credential.findBirthdayClaim()!;
    expect(birthdayIdx).not.toBeNull();

    const decodeFlags = data.claims.map((c) =>
      c.key === "roc_birthday" ? 1 : 0,
    );
    const additionalMatches = credential.disclosureHashes;

    const claimFormats = data.claims.map((c) =>
      c.key === "roc_birthday" ? 3 : 4,
    );

    const jwtInputs = buildJwtCircuitInputs(
      credential,
      data.issuerPublicKey,
      JWT_PARAMS_1K,
      additionalMatches,
      decodeFlags,
      claimFormats,
    );

    expect(jwtInputs.message.length).toBe(JWT_PARAMS_1K.maxMessageLength);

    const jwtInputsJson = circuitInputsToJson(jwtInputs);
    const jwtInputsParsed = JSON.parse(jwtInputsJson, (_key, value) => {
      if (typeof value === "string" && /^-?\d+$/.test(value))
        return BigInt(value);
      return value;
    });

    const jwtWitnessWtns =
      await jwtWitnessCalc.calculateWTNSBin(jwtInputsParsed);
    const jwtWitness =
      await jwtWitnessCalc.calculateWitness(jwtInputsParsed);

    const prepareResult = await bridge.precomputeFromWitness(
      preparePk,
      jwtWitnessWtns,
      "1k",
    );
    expect(prepareResult.proof.length).toBeGreaterThan(0);
    expect(prepareResult.instance.length).toBeGreaterThan(0);
    expect(prepareResult.witness.length).toBeGreaterThan(0);

    // Shared values Show must repeat, read from the private JWT witness.
    const maxClaims = JWT_PARAMS_1K.maxMatches - 2;
    const valuesStart = CLAIM_VALUES_WITNESS_START["1k"];
    const identityStart = CLAIM_IDENTITY_WITNESS_START["1k"];
    const normalizedClaimValues = jwtWitness.slice(valuesStart, valuesStart + maxClaims);
    const claimIdentifierHashes = jwtWitness.slice(identityStart, identityStart + maxClaims);
    const registry = createRevocationRegistry([1n, 2n, 3n]);

    const deviceSignature = signDeviceNonce(
      VERIFIER_NONCE,
      data.devicePrivateKeyHex,
    );
    const showInputs = buildShowCircuitInputs(
      DEFAULT_SHOW_PARAMS,
      VERIFIER_NONCE,
      deviceSignature,
      data.devicePublicKey,
      {
        normalizedClaimValues,
        claimIdentifierHashes,
        predicates: [],
        revocation: buildRevocationWitness(ISSUER_PUBLIC_KEY, REVOCATION_VALUE, registry),
      },
    );

    const showInputsJson = circuitInputsToJson(showInputs);
    const showInputsParsed = JSON.parse(showInputsJson, (_key, value) => {
      if (typeof value === "string" && /^-?\d+$/.test(value))
        return BigInt(value);
      return value;
    });

    const showWitnessWtns =
      await showWitnessCalc.calculateWTNSBin(showInputsParsed);
    const showWitness =
      await showWitnessCalc.calculateWitness(showInputsParsed);

    const showResult = await bridge.precomputeShowFromWitness(
      showPk,
      showWitnessWtns,
    );
    expect(showResult.proof.length).toBeGreaterThan(0);

    // Shared values match across circuits. JWT 1k: KeyBindingX/Y and
    // RevocationValue[2] follow claimIdentifierHashes, and the public issuer key
    // is at w[1..=2]. Show: deviceKeyX/Y at w[159..=160], then issuerKeyX/Y at
    // w[167..=168] and revocationValue[2] at w[169..=170], after
    // claimValues/claimIdentifierHashes.
    const keyStart = identityStart + maxClaims;
    expect(jwtWitness.slice(keyStart, keyStart + 2)).toEqual(showWitness.slice(159, 161));
    expect(jwtWitness.slice(1, 3)).toEqual(showWitness.slice(167, 169));
    expect(jwtWitness.slice(keyStart + 2, keyStart + 4)).toEqual(showWitness.slice(169, 171));

    const presentResult = await bridge.present(
      preparePk,
      prepareResult.instance,
      prepareResult.witness,
      showPk,
      showResult.instance,
      showResult.witness,
    );
    expect(presentResult.prepareProof.length).toBeGreaterThan(0);
    expect(presentResult.showProof.length).toBeGreaterThan(0);
    expect(presentResult.prepareInstance.length).toBeGreaterThan(0);
    expect(presentResult.showInstance.length).toBeGreaterThan(0);

    const verifyResult = await bridge.verify(
      presentResult.prepareProof,
      prepareVk,
      presentResult.prepareInstance,
      presentResult.showProof,
      showVk,
      presentResult.showInstance,
    );

    expect(verifyResult.valid).toBe(true);
    expect(verifyResult.error).toBeUndefined();
    // Show public IO: expressionResult, revocationRoot[2], then the 155-value
    // verifier statement. The device key and revocation value stay in comm_W_shared.
    expect(verifyResult.showPublicValues.length).toBe(158);
    // Prepare public IO is 2n + 2 for n = 2 claim slots: the issuer key
    // (pubKeyX, pubKeyY) then decodeFlags and claimFormats. Claim values and the
    // device key are private -- they used to hand the verifier the exact claim.
    expect(verifyResult.preparePublicValues.length).toBe(6);
    const provenIssuer = extractIssuerKeyFromPreparePublicValues(
      verifyResult.preparePublicValues.map(parseScalar),
    );
    expect(provenIssuer).toEqual(issuerPublicKeyToPoint(ISSUER_PUBLIC_KEY));
  }, 900_000);
},
);
