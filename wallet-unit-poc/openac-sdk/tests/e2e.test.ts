import { describe, it, expect, beforeAll } from "vitest";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2";

import {
  NativeBackend,
  WitnessCalculator,
  Credential,
  base64urlToBigInt,
  DEFAULT_JWT_PARAMS,
  DEFAULT_SHOW_PARAMS,
  buildRevocationWitness,
  createRevocationRegistry,
  encodeRevocationValue,
  buildIssuerMembershipInputs,
  createIssuerRegistry,
  issuerCommitment,
} from "../src/index.js";
import { buildJwtCircuitInputs } from "../src/inputs/jwt-input-builder.js";
import {
  buildShowCircuitInputs,
  signDeviceNonce,
} from "../src/inputs/show-input-builder.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ASSETS_DIR = join(__dirname, "..", "assets");

// The revocation value the issuer signs as `revocation_value`.
const REVOCATION_VALUE = 0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789n;

function derivePublicKey(privateKeyBytes: Uint8Array) {
  let hex = "";
  for (const b of privateKeyBytes) hex += b.toString(16).padStart(2, "0");
  return p256.ProjectivePoint.BASE.multiply(BigInt("0x" + hex));
}

// Fixed issuer key pair (deterministic for tests)
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

// Non-revocation inputs against an empty registry (root 0).
const REVOCATION = buildRevocationWitness(
  { x: ISSUER_POINT.x, y: ISSUER_POINT.y },
  REVOCATION_VALUE,
  createRevocationRegistry(),
);

// Show issuer inputs: the issuer above in a registry of just itself.
const ISSUER_MEMBERSHIP = buildIssuerMembershipInputs(
  { x: ISSUER_POINT.x, y: ISSUER_POINT.y },
  createIssuerRegistry([ISSUER_PUBLIC_KEY]).generateProof(issuerCommitment(ISSUER_PUBLIC_KEY)),
);

// Fixed device key pair (deterministic for tests)
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

/** Encode a JavaScript object as a base64url string. */
function jsonToBase64url(obj: unknown): string {
  const json = JSON.stringify(obj);
  return bytesToBase64url(new TextEncoder().encode(json));
}

/** Sign a JWT with ES256 (P-256 + SHA-256) using @noble/curves. */
function signES256(signingInput: string, privateKey: Uint8Array): string {
  const msgHash = sha256(signingInput);
  const sig = p256.sign(msgHash, privateKey);
  return bytesToBase64url(sig.toBytes("compact"));
}

/** Generate a base64url-encoded SD-JWT disclosure: base64url(JSON([salt, key, value])). */
function makeDisclosure(salt: string, key: string, value: string): string {
  const json = JSON.stringify([salt, key, value]);
  return bytesToBase64url(new TextEncoder().encode(json));
}

/** SHA-256 hash of a disclosure string, returned as base64url. */
function disclosureDigest(disclosure: string): string {
  const hash = sha256(new TextEncoder().encode(disclosure));
  return bytesToBase64url(hash);
}

interface TestJwtData {
  jwt: string;
  disclosures: string[];
  claims: Array<{ salt: string; key: string; value: string }>;
  issuerPublicKey: { kty: "EC"; crv: "P-256"; x: string; y: string };
  devicePublicKey: { kty: "EC"; crv: "P-256"; x: string; y: string };
  devicePrivateKeyHex: string;
}

/**
 * Generate a self-contained SD-JWT with known claims for testing.
 * Uses only @noble/curves: no external JWT library needed.
 */
function generateTestJwt(): TestJwtData {
  // Salts must be long enough so that each base64url-encoded disclosure is >= 56 bytes.
  // The circuit's ClaimHasher always processes claims as 2 SHA-256 blocks (maxClaimsLength=128).
  // If a disclosure is < 56 bytes, its SHA-256 padding fits in 1 block, causing a hash mismatch.
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

  const header = {
    alg: "ES256",
    typ: "vc+sd-jwt",
  };

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

describe("Credential Parsing via SDK", () => {
  it("parses SD-JWT and extracts claims", () => {
    const data = generateTestJwt();
    const credential = Credential.parse(data.jwt, data.disclosures);

    expect(credential.token).toBe(data.jwt);
    expect(credential.claims.length).toBe(data.disclosures.length);

    // Verify each claim was parsed correctly
    for (let i = 0; i < data.claims.length; i++) {
      expect(credential.claims[i]!.name).toBe(data.claims[i]!.key);
      expect(credential.claims[i]!.value).toBe(data.claims[i]!.value);
      expect(credential.claims[i]!.salt).toBe(data.claims[i]!.salt);
    }

    // Birthday claim detection
    const birthdayIdx = credential.findBirthdayClaim();
    expect(birthdayIdx).not.toBeNull();
    expect(credential.claims[birthdayIdx!]!.name).toBe("roc_birthday");
    expect(credential.claims[birthdayIdx!]!.value).toBe("0890615");
  });

  it("extracts device binding key from cnf.jwk", () => {
    const data = generateTestJwt();
    const credential = Credential.parse(data.jwt, data.disclosures);

    const deviceKey = credential.deviceBindingKey;
    expect(deviceKey).not.toBeNull();
    expect(deviceKey!.kty).toBe("EC");
    expect(deviceKey!.crv).toBe("P-256");
    expect(deviceKey!.x).toBe(data.devicePublicKey.x);
    expect(deviceKey!.y).toBe(data.devicePublicKey.y);
  });

  it("computes disclosure digests matching _sd array", () => {
    const data = generateTestJwt();
    const credential = Credential.parse(data.jwt, data.disclosures);

    const sdDigests = credential.sdDigests;
    const computedDigests = credential.disclosureHashes;

    expect(sdDigests.length).toBe(computedDigests.length);
    for (let i = 0; i < sdDigests.length; i++) {
      expect(computedDigests).toContain(sdDigests[i]);
    }
  });
});

describe("Input Builders via SDK", () => {
  it("buildShowCircuitInputs rejects missing issuer inputs", () => {
    const signature = signDeviceNonce(VERIFIER_NONCE, DEVICE_PRIVATE_KEY_HEX);
    expect(() =>
      buildShowCircuitInputs(DEFAULT_SHOW_PARAMS, VERIFIER_NONCE, signature, DEVICE_PUBLIC_KEY, {
        revocation: REVOCATION,
      }),
    ).toThrow(expect.objectContaining({ code: "MISSING_ISSUER_INPUTS" }));
  });

  it("buildShowCircuitInputs creates valid circuit inputs", () => {
    // Derive the correct public key from the device private key
    const deviceKey = DEVICE_PUBLIC_KEY;
    const signature = signDeviceNonce(VERIFIER_NONCE, DEVICE_PRIVATE_KEY_HEX);

    const inputs = buildShowCircuitInputs(
      DEFAULT_SHOW_PARAMS,
      VERIFIER_NONCE,
      signature,
      deviceKey,
      { revocation: REVOCATION, issuer: ISSUER_MEMBERSHIP },
    );

    expect(inputs.deviceKeyX).toBeDefined();
    expect(inputs.deviceKeyY).toBeDefined();
    expect(inputs.sig_r).toBeDefined();
    expect(inputs.sig_s_inverse).toBeDefined();
    expect(inputs.messageHash).toBeDefined();
    expect(inputs.claimValues.length).toBe(DEFAULT_SHOW_PARAMS.nClaims);
    expect(inputs.predicateClaimRefs.length).toBe(DEFAULT_SHOW_PARAMS.maxPredicates);
    expect(inputs.predicateOps.length).toBe(DEFAULT_SHOW_PARAMS.maxPredicates);
    expect(inputs.predicateRhsIsRef.length).toBe(DEFAULT_SHOW_PARAMS.maxPredicates);
    expect(inputs.predicateRhsValues.length).toBe(DEFAULT_SHOW_PARAMS.maxPredicates);
    expect(inputs.tokenTypes.length).toBe(DEFAULT_SHOW_PARAMS.maxLogicTokens);
    expect(inputs.tokenValues.length).toBe(DEFAULT_SHOW_PARAMS.maxLogicTokens);

    // Verify the device key coordinates match
    expect(inputs.deviceKeyX).toBe(base64urlToBigInt(deviceKey.x));
    expect(inputs.deviceKeyY).toBe(base64urlToBigInt(deviceKey.y));
  });

  it("buildJwtCircuitInputs creates valid circuit inputs from generated JWT", () => {
    const data = generateTestJwt();
    const credential = Credential.parse(data.jwt, data.disclosures);

    const birthdayIdx = credential.findBirthdayClaim();
    expect(birthdayIdx).not.toBeNull();

    const decodeFlags = data.claims.map((c) =>
      c.key === "roc_birthday" ? 1 : 0,
    );
    const additionalMatches = credential.disclosureHashes;

    const claimFormats = data.claims.map((c) =>
      c.key === "roc_birthday" ? 3 : 4,
    );

    const inputs = buildJwtCircuitInputs(
      credential,
      data.issuerPublicKey,
      DEFAULT_JWT_PARAMS,
      additionalMatches,
      decodeFlags,
      claimFormats,
    );

    expect(inputs.sig_r).toBeDefined();
    expect(inputs.sig_s_inverse).toBeDefined();
    expect(inputs.pubKeyX).toBeDefined();
    expect(inputs.pubKeyY).toBeDefined();
    expect(inputs.message.length).toBe(DEFAULT_JWT_PARAMS.maxMessageLength);
    expect(inputs.messageLength).toBeGreaterThan(0);
    expect(inputs.periodIndex).toBeGreaterThan(0);
    expect(inputs.matchesCount).toBe(additionalMatches.length + 2); // +2 for "x":" and "y":"
    expect(inputs.claimFormats.length).toBe(DEFAULT_JWT_PARAMS.maxMatches - 2);
  });
});

describe("Show Circuit via SDK", () => {
  let witnessCalculator: WitnessCalculator;

  beforeAll(async () => {
    witnessCalculator = new WitnessCalculator(ASSETS_DIR);
    await witnessCalculator.init();
  });

  it("generates valid show witness from SDK-built inputs", async () => {
    const data = generateTestJwt();

    // Sign device nonce via SDK
    const signature = signDeviceNonce(VERIFIER_NONCE, data.devicePrivateKeyHex);

    // Build Show circuit inputs via SDK with a simple predicate
    // Empty policy: no active predicate, so the claim-identity binding (which
    // needs real H(name) from the Prepare witness, unavailable in this isolated
    // Show-only smoke test) is gated off. This just checks the SDK builds a
    // witness-satisfiable Show input.
    const showInputs = buildShowCircuitInputs(
      DEFAULT_SHOW_PARAMS,
      VERIFIER_NONCE,
      signature,
      data.devicePublicKey,
      {
        normalizedClaimValues: [42n],
        predicates: [],
        revocation: REVOCATION,
        issuer: ISSUER_MEMBERSHIP,
      },
    );

    // Calculate witness via SDK WitnessCalculator
    const witness = await witnessCalculator.calculateShowWitness(showInputs);

    // Witness sanity checks
    expect(witness[0]).toBe(1n); // valid constraint system
    // Witness layout: w[1] = expressionResult, w[2..=3] = issuerRoot[hi, lo],
    // w[4..=5] = revocationRoot (0 for an empty registry), w[6..=160] = messageHash
    // + predicate program, then private signals: w[161..=162] = deviceKeyX/Y.
    expect([witness[4], witness[5]]).toEqual([0n, 0n]); // revocationRoot
    expect(witness[6]).toBe(showInputs.messageHash); // messageHash (public)
    expect(witness[161]).toBe(base64urlToBigInt(data.devicePublicKey.x)); // deviceKeyX
    expect(witness[162]).toBe(base64urlToBigInt(data.devicePublicKey.y)); // deviceKeyY
  }, 30_000);

  it("proves and verifies via NativeBackend", async () => {
    const backend = new NativeBackend();
    if (!backend.keysExist) return;

    await backend.proveShow();
    const result = await backend.verifyShow();

    expect(result.valid).toBe(true);
    expect(result.output).toContain("Verification successful");
  }, 120_000);
});

describe("JWT (Prepare) Circuit via SDK", () => {
  let witnessCalculator: WitnessCalculator;

  beforeAll(async () => {
    witnessCalculator = new WitnessCalculator(ASSETS_DIR);
    await witnessCalculator.init();
  });

  it("generates valid JWT witness from SDK-built inputs", async () => {
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

    // Build JWT circuit inputs via SDK
    const jwtInputs = buildJwtCircuitInputs(
      credential,
      data.issuerPublicKey,
      DEFAULT_JWT_PARAMS,
      additionalMatches,
      decodeFlags,
      claimFormats,
    );

    // Calculate witness via SDK WitnessCalculator
    const witness = await witnessCalculator.calculateJwtWitness(jwtInputs);

    // Witness sanity checks
    expect(witness[0]).toBe(1n); // valid constraint system
    // The JWT circuit has no public outputs. Claim values would reveal the exact
    // attribute; the device key would be a constant identifier linking every
    // presentation. Both are private and reach Show via comm_W_shared.
    // `identifierStart` is the witness index of claimIdentifierHashes[0], which
    // is followed by KeyBindingX/Y. This exercises the default `jwt` circuit
    // (maxMessageLength 1920), not a VcSize variant, so it needs its own offset.
    // These are private signals, so circom assigns their positions and they move
    // whenever the constraint system changes. Re-derive after any circuit edit:
    //   grep -m1 'main.claimIdentifierHashes\[0\]' circom/build/jwt/jwt.sym
    // (field 2 of that line is the witness index).
    const identifierStart = 3872;
    const maxClaims = DEFAULT_JWT_PARAMS.maxMatches - 2;
    expect(witness.length).toBeGreaterThan(identifierStart + maxClaims + 1);

    expect(witness[identifierStart + maxClaims]).toBe(
      base64urlToBigInt(data.devicePublicKey.x),
    );
    expect(witness[identifierStart + maxClaims + 1]).toBe(
      base64urlToBigInt(data.devicePublicKey.y),
    );
    // RevocationValue [hi, lo] follows the device key.
    expect(witness.slice(identifierStart + maxClaims + 2, identifierStart + maxClaims + 4)).toEqual(
      REVOCATION.revocationValue,
    );
  }, 120_000);

  it("proves and verifies via NativeBackend", async () => {
    const backend = new NativeBackend();
    if (!backend.keysExist) return;

    await backend.provePrepare();
    const result = await backend.verifyPrepare();

    expect(result.valid).toBe(true);
    expect(result.output).toContain("Verification successful");
  }, 360_000);
});

describe("Full Pipeline via SDK (Prepare + Show with Shared Blinds)", () => {
  let backend: NativeBackend;
  let witnessCalculator: WitnessCalculator;

  beforeAll(async () => {
    backend = new NativeBackend();
    witnessCalculator = new WitnessCalculator(ASSETS_DIR);
    await witnessCalculator.init();
  });

  it("runs complete pipeline using SDK from JWT generation to verification", async () => {
    if (!backend.keysExist) return;

    // Step 1: Generate test JWT using self-contained helper
    const data = generateTestJwt();

    // Step 2: Parse credential via SDK
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

    // Step 3: Build JWT circuit inputs via SDK
    const jwtInputs = buildJwtCircuitInputs(
      credential,
      data.issuerPublicKey,
      DEFAULT_JWT_PARAMS,
      additionalMatches,
      decodeFlags,
      claimFormats,
    );

    // Step 4: Calculate JWT witness and prove Prepare circuit
    const jwtWitness = await witnessCalculator.calculateJwtWitness(jwtInputs);
    await backend.generateSharedBlinds();
    await backend.provePrepare();
    await backend.reblindPrepare();

    // Step 5: Build Show circuit inputs via SDK
    // Extract normalizedClaimValues from JWT witness for shared witness consistency
    const maxClaims = DEFAULT_JWT_PARAMS.maxMatches - 2;
    const normalizedClaimValues = jwtWitness.slice(1, 1 + maxClaims);

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
        revocation: REVOCATION,
        issuer: ISSUER_MEMBERSHIP,
      },
    );

    // Step 6: Calculate Show witness and prove Show circuit
    const showWitness =
      await witnessCalculator.calculateShowWitness(showInputs);
    await backend.proveShow();
    await backend.reblindShow();

    // Step 7: Verify both proofs via SDK
    const prepResult = await backend.verifyPrepare();
    const showResult = await backend.verifyShow();

    expect(prepResult.valid).toBe(true);
    expect(prepResult.output).toContain("Verification successful");
    expect(showResult.valid).toBe(true);
    expect(showResult.output).toContain("Verification successful");

    // Step 8: Cross-circuit consistency: device key from JWT must match Show.
    // JWT circuit (maxMatches=4): w[3] = KeyBindingX, w[4] = KeyBindingY.
    // In Show, the verifier statement occupies the public prefix (w[1..=28]),
    // so the device key sits at w[29] = deviceKeyX, w[30] = deviceKeyY.
    expect(jwtWitness[3]).toBe(showWitness[29]); // KeyBindingX
    expect(jwtWitness[4]).toBe(showWitness[30]); // KeyBindingY

    // Step 9: Expression evaluation result
    expect(typeof showWitness[1]).toBe("bigint"); // expressionResult
  }, 900_000);

  it("can load keys and proofs via SDK", async () => {
    if (!backend.keysExist) return;
    if (!backend.proofsExist) return;

    const keys = await backend.loadKeys();
    expect(keys.prepareProvingKey.length).toBeGreaterThan(0);
    expect(keys.prepareVerifyingKey.length).toBeGreaterThan(0);
    expect(keys.showProvingKey.length).toBeGreaterThan(0);
    expect(keys.showVerifyingKey.length).toBeGreaterThan(0);

    const verifyingKeys = keys.verifyingKeys();
    expect(verifyingKeys.prepareVerifyingKey).toBe(keys.prepareVerifyingKey);
    expect(verifyingKeys.showVerifyingKey).toBe(keys.showVerifyingKey);

    const proofs = await backend.loadProofs();
    expect(proofs.prepareProof.length).toBeGreaterThan(0);
    expect(proofs.showProof.length).toBeGreaterThan(0);
  }, 30_000);
});
