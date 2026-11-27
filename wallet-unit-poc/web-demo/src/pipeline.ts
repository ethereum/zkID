/**
 * zkID Full Pipeline — Browser implementation.
 *
 * Mirrors the E2E test "Full Pipeline via SDK (Prepare + Show with Shared Blinds)"
 * but uses WasmBridge (browser WASM) instead of NativeBackend (Rust CLI).
 *
 * Steps:
 *   1. Generate Test JWT (pure JS, deterministic keys)
 *   2. Precompute: parse credential, build JWT inputs, witness, prove Prepare
 *   3. Present: sign nonce, build Show inputs, witness, prove Show, reblind both
 *   4. Verify: verify both proofs + shared commitment
 */

import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha2";

// Import browser-safe SDK source files directly (avoids NativeBackend / fs deps)
import { Credential } from "../../openac-sdk/src/credential.js";
import { WasmBridge } from "../../openac-sdk/src/wasm-bridge.js";
import type { VcSize } from "../../openac-sdk/src/wasm-bridge.js";
import wasmUrl from "../../openac-sdk/wasm/pkg/openac_wasm_bg.wasm?url";
import { buildJwtCircuitInputs } from "../../openac-sdk/src/inputs/jwt-input-builder.js";
import {
  buildShowCircuitInputs,
  signDeviceNonce,
} from "../../openac-sdk/src/inputs/show-input-builder.js";
import {
  circuitInputsToJson,
  base64urlToBigInt,
} from "../../openac-sdk/src/utils.js";
import { extractIssuerKeyFromPreparePublicValues } from "../../openac-sdk/src/inputs/prepare-public-io.js";
import { DEFAULT_SHOW_PARAMS } from "../../openac-sdk/src/types.js";
import type { JwtCircuitParams } from "../../openac-sdk/src/types.js";

import { BrowserWitnessCalculator } from "./witness-calc-browser.js";

// Circuit params must match the compiled circuit variant.
// jwt_1k uses params [1280, 960, 4, 50, 128] (see circom/circuits.json).
// DEFAULT_JWT_PARAMS has maxMessageLength=1920 which is for the default (larger) circuit.
const JWT_PARAMS_1K: JwtCircuitParams = {
  maxMessageLength: 1280,
  maxB64PayloadLength: 960,
  maxMatches: 4,
  maxSubstringLength: 50,
  maxClaimLength: 128,
};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface StepLog {
  label: string;
  durationMs: number;
}

export interface GenerateResult {
  jwt: string;
  disclosures: string[];
  claims: Array<{ salt: string; key: string; value: string }>;
  issuerPublicKey: { kty: "EC"; crv: "P-256"; x: string; y: string };
  devicePublicKey: { kty: "EC"; crv: "P-256"; x: string; y: string };
  devicePrivateKeyHex: string;
  logs: StepLog[];
  totalMs: number;
}

export interface PrecomputeResult {
  prepareProof: Uint8Array;
  prepareInstance: Uint8Array;
  prepareWitness: Uint8Array;
  jwtWitness: bigint[];
  credential: Credential;
  birthdayClaimIndex: number;
  logs: StepLog[];
  totalMs: number;
}

export interface PresentResult {
  prepareProof: Uint8Array;
  prepareInstance: Uint8Array;
  showProof: Uint8Array;
  showInstance: Uint8Array;
  showWitness: bigint[];
  ageAbove18: boolean;
  logs: StepLog[];
  totalMs: number;
}

export interface VerifyResult {
  valid: boolean;
  ageAbove18: boolean;
  deviceKey: { x: string; y: string } | null;
  /** True when the Prepare proof was built under the demo's expected issuer key. */
  issuerTrusted: boolean;
  error?: string;
  logs: StepLog[];
  totalMs: number;
}

// ---------------------------------------------------------------------------
// Encoding helpers (same as e2e test — pure, no Node.js Buffer)
// ---------------------------------------------------------------------------

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

function derivePublicKey(privateKeyBytes: Uint8Array) {
  let hex = "";
  for (const b of privateKeyBytes) hex += b.toString(16).padStart(2, "0");
  return p256.ProjectivePoint.BASE.multiply(BigInt("0x" + hex));
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

// ---------------------------------------------------------------------------
// Fixed test keys (deterministic, same as e2e.test.ts)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Pipeline state (singleton)
// ---------------------------------------------------------------------------

let bridge: WasmBridge | null = null;
let witnessCalc: BrowserWitnessCalculator | null = null;
let keys: {
  preparePk: Uint8Array;
  prepareVk: Uint8Array;
  showPk: Uint8Array;
  showVk: Uint8Array;
} | null = null;

// State carried between steps
let currentTestData: GenerateResult | null = null;
let currentPrecompute: PrecomputeResult | null = null;
let currentPresent: PresentResult | null = null;

// ---------------------------------------------------------------------------
// Step 0: Initialize WASM + load keys (called once)
// ---------------------------------------------------------------------------

// Must match abi_version() in openac-sdk/wasm/src/lib.rs.
const ABI_VERSION = 1;

export type ProgressCallback = (message: string) => void;

export async function initWasm(
  onProgress?: ProgressCallback
): Promise<StepLog[]> {
  const logs: StepLog[] = [];

  // 1. Load WASM module
  //    Glue and binary come straight from openac-sdk/wasm/pkg, so the demo
  //    always runs the verifier that was last built there.
  onProgress?.("Loading WASM module...");
  let t = performance.now();
  const wasmModule = await import("../../openac-sdk/wasm/pkg/openac_wasm.js");
  const wasmResp = await fetch(wasmUrl);
  const wasmBytes = await wasmResp.arrayBuffer();
  wasmModule.initSync({ module: new WebAssembly.Module(wasmBytes) });
  const abi = wasmModule.abi_version();
  if (abi !== ABI_VERSION) {
    throw new Error(
      `Verifier WASM ABI mismatch: expected ${ABI_VERSION}, got ${abi}. ` +
        "openac-sdk/wasm/pkg is stale; rebuild it with `npm run build:wasm` in openac-sdk."
    );
  }

  bridge = new WasmBridge();
  bridge.initWithModule(wasmModule);
  logs.push({ label: "Load WASM module", durationMs: performance.now() - t });

  // 2. Initialize witness calculator
  onProgress?.("Initializing witness calculator...");
  t = performance.now();
  witnessCalc = new BrowserWitnessCalculator();
  logs.push({
    label: "Init witness calculator",
    durationMs: performance.now() - t,
  });

  // 3. Load keys
  onProgress?.("Loading proving/verifying keys (1k)...");
  t = performance.now();
  const vcSize: VcSize = "1k";
  keys = await bridge.loadKeys("/keys", vcSize);
  logs.push({ label: "Load keys (1k)", durationMs: performance.now() - t });

  return logs;
}

// ---------------------------------------------------------------------------
// Step 1: Generate Test Case
// ---------------------------------------------------------------------------

export function generateTestCase(): GenerateResult {
  const t0 = performance.now();
  const logs: StepLog[] = [];

  let t = performance.now();
  const claimDefs = [
    { salt: "aGVsbG9fd29ybGRfMTIzNDU2", key: "name", value: "Alice" },
    {
      salt: "Z29vZGJ5ZV93b3JsZF83ODkwMTI",
      key: "roc_birthday",
      value: "0890615",
    },
  ];

  const disclosures = claimDefs.map((c) =>
    makeDisclosure(c.salt, c.key, c.value)
  );
  const hashedClaims = disclosures.map((d) => disclosureDigest(d));

  const header = { alg: "ES256", typ: "vc+sd-jwt" };
  const payload = {
    sub: "did:example:subject",
    iss: "did:example:issuer",
    nbf: 1700000000,
    exp: 1800000000,
    cnf: { jwk: DEVICE_PUBLIC_KEY },
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
  logs.push({ label: "Generate SD-JWT", durationMs: performance.now() - t });

  const result: GenerateResult = {
    jwt,
    disclosures,
    claims: claimDefs,
    issuerPublicKey: ISSUER_PUBLIC_KEY,
    devicePublicKey: DEVICE_PUBLIC_KEY,
    devicePrivateKeyHex: DEVICE_PRIVATE_KEY_HEX,
    logs,
    totalMs: performance.now() - t0,
  };

  currentTestData = result;
  return result;
}

// ---------------------------------------------------------------------------
// Step 2: Precompute (Prepare circuit)
// ---------------------------------------------------------------------------

export async function precompute(
  onProgress?: ProgressCallback
): Promise<PrecomputeResult> {
  if (!currentTestData) throw new Error("Run Step 1 first");
  if (!bridge) throw new Error("WASM not initialized");
  if (!witnessCalc) throw new Error("Witness calculator not initialized");
  if (!keys) throw new Error("Keys not loaded");

  const data = currentTestData;
  const t0 = performance.now();
  const logs: StepLog[] = [];

  // Parse credential
  onProgress?.("Parsing credential...");
  let t = performance.now();
  const credential = Credential.parse(data.jwt, data.disclosures);
  const birthdayIdx = credential.findBirthdayClaim()!;
  logs.push({ label: "Parse credential", durationMs: performance.now() - t });

  // Build JWT circuit inputs
  onProgress?.("Building JWT circuit inputs...");
  t = performance.now();
  const decodeFlags = data.claims.map((c) =>
    c.key === "roc_birthday" ? 1 : 0
  );
  const additionalMatches = credential.disclosureHashes;

  const jwtInputs = buildJwtCircuitInputs(
    credential,
    data.issuerPublicKey,
    JWT_PARAMS_1K,
    additionalMatches,
    decodeFlags,
    birthdayIdx
  );
  logs.push({
    label: "Build JWT circuit inputs",
    durationMs: performance.now() - t,
  });

  // Calculate JWT witness (Circom WASM)
  onProgress?.("Calculating JWT witness (circom WASM)...");
  t = performance.now();
  const jwtInputsJson = circuitInputsToJson(jwtInputs);
  const jwtInputsParsed = JSON.parse(jwtInputsJson, (_key, value) => {
    if (typeof value === "string" && /^-?\d+$/.test(value)) return BigInt(value);
    return value;
  });
  const jwtWitnessWtns = await witnessCalc.calculateJwtWitnessWtns(jwtInputsParsed);
  const jwtWitness = await witnessCalc.calculateJwtWitness(jwtInputsParsed);
  logs.push({
    label: "Calculate JWT witness",
    durationMs: performance.now() - t,
  });

  // Prove Prepare circuit (Spartan2 WASM)
  onProgress?.("Proving Prepare circuit (Spartan2 WASM)...");
  t = performance.now();
  const prepareResult = await bridge.precomputeFromWitness(
    keys.preparePk,
    jwtWitnessWtns
  );
  logs.push({
    label: "Prove Prepare circuit",
    durationMs: performance.now() - t,
  });

  const result: PrecomputeResult = {
    prepareProof: prepareResult.proof,
    prepareInstance: prepareResult.instance,
    prepareWitness: prepareResult.witness,
    jwtWitness,
    credential,
    birthdayClaimIndex: birthdayIdx,
    logs,
    totalMs: performance.now() - t0,
  };

  currentPrecompute = result;
  return result;
}

// ---------------------------------------------------------------------------
// Step 3: Present (Show circuit + reblind)
// ---------------------------------------------------------------------------

export async function present(
  onProgress?: ProgressCallback
): Promise<PresentResult> {
  if (!currentTestData) throw new Error("Run Step 1 first");
  if (!currentPrecompute) throw new Error("Run Step 2 first");
  if (!bridge) throw new Error("WASM not initialized");
  if (!witnessCalc) throw new Error("Witness calculator not initialized");
  if (!keys) throw new Error("Keys not loaded");

  const data = currentTestData;
  const precomp = currentPrecompute;
  const t0 = performance.now();
  const logs: StepLog[] = [];

  // Sign verifier nonce with device key
  onProgress?.("Signing verifier nonce...");
  let t = performance.now();
  const deviceSignature = signDeviceNonce(
    VERIFIER_NONCE,
    data.devicePrivateKeyHex
  );
  logs.push({
    label: "Sign verifier nonce",
    durationMs: performance.now() - t,
  });

  // Build Show circuit inputs
  onProgress?.("Building Show circuit inputs...");
  t = performance.now();
  const birthdayClaim = data.disclosures[precomp.birthdayClaimIndex]!;
  const showInputs = buildShowCircuitInputs(
    DEFAULT_SHOW_PARAMS,
    VERIFIER_NONCE,
    deviceSignature,
    data.devicePublicKey,
    birthdayClaim,
    { year: 2025, month: 1, day: 1 }
  );
  logs.push({
    label: "Build Show circuit inputs",
    durationMs: performance.now() - t,
  });

  // Calculate Show witness (Circom WASM)
  onProgress?.("Calculating Show witness (circom WASM)...");
  t = performance.now();
  const showInputsJson = circuitInputsToJson(showInputs);
  const showInputsParsed = JSON.parse(showInputsJson, (_key, value) => {
    if (typeof value === "string" && /^-?\d+$/.test(value)) return BigInt(value);
    return value;
  });
  const showWitnessWtns = await witnessCalc.calculateShowWitnessWtns(showInputsParsed);
  const showWitness = await witnessCalc.calculateShowWitness(showInputsParsed);
  logs.push({
    label: "Calculate Show witness",
    durationMs: performance.now() - t,
  });

  // Prove Show circuit (Spartan2 WASM)
  onProgress?.("Proving Show circuit (Spartan2 WASM)...");
  t = performance.now();
  const showResult = await bridge.precomputeShowFromWitness(
    keys.showPk,
    showWitnessWtns
  );
  logs.push({
    label: "Prove Show circuit",
    durationMs: performance.now() - t,
  });

  // Reblind both proofs with shared randomness (present)
  onProgress?.("Reblinding proofs (shared randomness)...");
  t = performance.now();
  const presentResult = await bridge.present(
    keys.preparePk,
    precomp.prepareInstance,
    precomp.prepareWitness,
    keys.showPk,
    showResult.instance,
    showResult.witness
  );
  logs.push({
    label: "Reblind both proofs",
    durationMs: performance.now() - t,
  });

  // Cross-circuit consistency check (same as e2e test steps 8-9)
  const jwtWitness = precomp.jwtWitness;
  const keyBindingXMatch = jwtWitness[97] === showWitness[2]; // KeyBindingX
  const keyBindingYMatch = jwtWitness[98] === showWitness[3]; // KeyBindingY
  const ageAbove18 = showWitness[1] === 1n;

  if (!keyBindingXMatch || !keyBindingYMatch) {
    console.warn(
      "Cross-circuit key binding mismatch — device keys do not match"
    );
  }

  const result: PresentResult = {
    prepareProof: presentResult.prepareProof,
    prepareInstance: presentResult.prepareInstance,
    showProof: presentResult.showProof,
    showInstance: presentResult.showInstance,
    showWitness,
    ageAbove18,
    logs,
    totalMs: performance.now() - t0,
  };

  currentPresent = result;
  return result;
}

// ---------------------------------------------------------------------------
// Step 4: Verify
// ---------------------------------------------------------------------------

/** Parse a WASM-formatted public value (Rust `{:?}` on a field element) into a bigint. */
function parseScalarString(value: string): bigint {
  const hex = value.match(/0x([0-9a-fA-F]+)/);
  if (hex) return BigInt("0x" + hex[1]);
  const dec = value.match(/-?\d+/);
  return dec ? BigInt(dec[0]) : 0n;
}

export async function verify(
  onProgress?: ProgressCallback
): Promise<VerifyResult> {
  if (!currentPresent) throw new Error("Run Step 3 first");
  if (!bridge) throw new Error("WASM not initialized");
  if (!keys) throw new Error("Keys not loaded");

  const pres = currentPresent;
  const t0 = performance.now();
  const logs: StepLog[] = [];

  onProgress?.("Verifying both proofs + shared commitment...");
  const t = performance.now();
  const verifyResult = await bridge.verify(
    pres.prepareProof,
    keys.prepareVk,
    pres.prepareInstance,
    pres.showProof,
    keys.showVk,
    pres.showInstance
  );
  logs.push({
    label: "Verify proofs",
    durationMs: performance.now() - t,
  });

  // Extract public values from verification result
  let ageAbove18 = false;
  let deviceKey: { x: string; y: string } | null = null;
  // The Prepare proof's public IO carries the (pubKeyX, pubKeyY) the circuit
  // ran its ES256 check against. Proof validity does not cover issuer identity,
  // so compare that key against the issuer this demo expects.
  let issuerTrusted = false;

  if (verifyResult.valid) {
    const provenIssuer = extractIssuerKeyFromPreparePublicValues(
      verifyResult.preparePublicValues.map(parseScalarString),
    );
    issuerTrusted =
      provenIssuer.x === base64urlToBigInt(ISSUER_PUBLIC_KEY.x) &&
      provenIssuer.y === base64urlToBigInt(ISSUER_PUBLIC_KEY.y);
  }

  if (verifyResult.valid) {
    // Show public IO is now [expressionResult, messageHash, predicate program,
    // attribute names, ...] (156 signals). Only index 0 (expressionResult) is a
    // consumer value here. The device key is PRIVATE (reaches Show via
    // comm_W_shared), so it is intentionally NOT in showPublicValues and must
    // not be read from spv[1]/spv[2] (that used to read the old 3-value layout).
    const spv = verifyResult.showPublicValues;
    if (spv.length >= 1) {
      const cleaned = (spv[0] ?? "").replace(/^0x/, "").replace(/[^0-9a-fA-F]/g, "");
      ageAbove18 = cleaned.length > 0 && !/^0+$/.test(cleaned);
    }
    // deviceKey stays null: it is private and not exposed by the proof.
  }

  return {
    valid: verifyResult.valid && issuerTrusted,
    ageAbove18,
    deviceKey,
    issuerTrusted,
    error:
      verifyResult.valid && !issuerTrusted
        ? "Untrusted issuer: credential was not signed by the expected issuer key"
        : verifyResult.error,
    logs,
    totalMs: performance.now() - t0,
  };
}

// ---------------------------------------------------------------------------
// Utilities for UI display
// ---------------------------------------------------------------------------

export function getDevicePublicKeyDisplay(): {
  x: string;
  y: string;
} {
  return {
    x: base64urlToBigInt(DEVICE_PUBLIC_KEY.x).toString(16).slice(0, 16) + "...",
    y: base64urlToBigInt(DEVICE_PUBLIC_KEY.y).toString(16).slice(0, 16) + "...",
  };
}

export function getIssuerPublicKeyDisplay(): {
  x: string;
  y: string;
} {
  return {
    x: base64urlToBigInt(ISSUER_PUBLIC_KEY.x).toString(16).slice(0, 16) + "...",
    y: base64urlToBigInt(ISSUER_PUBLIC_KEY.y).toString(16).slice(0, 16) + "...",
  };
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function formatMs(ms: number): string {
  if (ms < 1000) return `${ms.toFixed(0)}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}
