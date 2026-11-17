// Public-API e2e tests for the OpenAC SDK.
// Set OPENAC_KEYS_URL=https://pub-<hash>.r2.dev to additionally exercise R2 fetch.

import { describe, it, expect, beforeAll } from "vitest";
import { existsSync, readFileSync } from "fs";
import { readFile } from "fs/promises";
import { createHash } from "crypto";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

import {
  OpenAC,
  Credential,
  compilePredicateExpression,
  requiredNormalization,
  acceptRevocationRoots,
  computeRevocationCommitment,
  createRevocationRegistry,
  generateRevocationSecret,
  createIssuerRegistry,
  issuerCommitment,
  acceptIssuerRoots,
} from "../src/index.js";
import { generateDummyCredential, issuerProofFor } from "../src/testing/index.js";
import type { VcSize } from "../src/sizing.js";
import type { KeySet, VerifyingKeys, ExpectedStatement } from "../src/types.js";
import type { PredicateExpression } from "../src/predicates.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ASSETS_DIR = join(__dirname, "..", "assets");
const KEYS_DIR = join(__dirname, "..", "..", "ecdsa-spartan2", "keys");
const WASM_PKG_DIR = join(__dirname, "..", "wasm", "pkg");

const R2_BASE_URL = (process.env.OPENAC_KEYS_URL ?? "").trim();
const HAS_R2 = R2_BASE_URL.startsWith("https://");
const HAS_LOCAL_1K = existsSync(join(KEYS_DIR, "1k_show_proving.key"));
const HAS_LOCAL_2K = existsSync(join(KEYS_DIR, "2k_show_proving.key"));

async function loadWasmModule() {
  const mod = await import(
    /* webpackIgnore: true */ join(WASM_PKG_DIR, "openac_wasm.js")
  );
  const bin = await readFile(join(WASM_PKG_DIR, "openac_wasm_bg.wasm"));
  mod.initSync({ module: bin });
  return mod;
}

function loadLocalKeySet(size: VcSize): KeySet {
  const prepareProvingKey = new Uint8Array(
    readFileSync(join(KEYS_DIR, `${size}_prepare_proving.key`)),
  );
  const prepareVerifyingKey = new Uint8Array(
    readFileSync(join(KEYS_DIR, `${size}_prepare_verifying.key`)),
  );
  const showProvingKey = new Uint8Array(
    readFileSync(join(KEYS_DIR, `${size}_show_proving.key`)),
  );
  const showVerifyingKey = new Uint8Array(
    readFileSync(join(KEYS_DIR, `${size}_show_verifying.key`)),
  );
  return {
    prepareProvingKey,
    prepareVerifyingKey,
    showProvingKey,
    showVerifyingKey,
    verifyingKeys(): VerifyingKeys {
      return { prepareVerifyingKey, showVerifyingKey };
    },
    serialize() {
      return {
        prepareProvingKey,
        prepareVerifyingKey,
        showProvingKey,
        showVerifyingKey,
      };
    },
  };
}

function sha256Hex(buf: Uint8Array): string {
  return createHash("sha256").update(buf).digest("hex");
}

// Other holders' revoked commitments; the test credentials are not in it.
const REGISTRY = createRevocationRegistry(
  Array.from({ length: 6 }, () => computeRevocationCommitment(generateRevocationSecret())),
);

function revocationFor(cred: { revocationSecretHex: string }) {
  return { secret: cred.revocationSecretHex, registry: REGISTRY };
}

function makeDummy1k() {
  return generateDummyCredential({
    size: "1k",
    claims: [
      { key: "roc_birthday", value: "0900101" },
      { key: "roc_max", value: "0950101" },
    ],
  });
}

const claimToClaimPredicate = {
  claim: "roc_birthday",
  op: "<=" as const,
  compareTo: { claim: "roc_max" },
};

/**
 * Build the verifier's expected statement. The verify API takes the predicate
 * program in circuit (claim-index) form and never sees the holder's claims; a
 * real verifier derives that program from its credential schema. Here the test
 * compiles it once against the schema (the dummy credential's claim layout).
 */
function expectedStatement(
  cred: ReturnType<typeof makeDummy1k>,
  nonce: string,
  predicates: PredicateExpression,
): ExpectedStatement {
  const schema = Credential.parse(cred.jwt, cred.disclosures).claims;
  const compiled = compilePredicateExpression(predicates, schema);
  return {
    nonce,
    predicates: compiled.predicates,
    logicExpression: compiled.logicExpression,
    claimNormalization: requiredNormalization(compiled),
    // issuerProofFor proves against a registry of just the credential's issuer.
    isValidIssuerRoot: acceptIssuerRoots([createIssuerRegistry([cred.issuerPublicKey]).root]),
    isValidRevocationRoot: acceptRevocationRoots([REGISTRY.root]),
  };
}

describe("OpenAC: initialization", () => {
  it("init() returns an OpenAC instance reporting isReady=true", async () => {
    const wasmModule = await loadWasmModule();
    const openac = await OpenAC.init({ assetsDir: ASSETS_DIR, wasmModule });
    expect(openac).toBeInstanceOf(OpenAC);
    expect(openac.isReady).toBe(true);
  });

  it("init() accepts keysBaseUrl in OpenACConfig", async () => {
    const wasmModule = await loadWasmModule();
    const openac = await OpenAC.init({
      assetsDir: ASSETS_DIR,
      wasmModule,
      keysBaseUrl: "https://example.invalid/keys",
    });
    expect(openac.isReady).toBe(true);
  });
});

describe("OpenAC.loadBundledShowVerifyingKey", () => {
  let openac: OpenAC;
  const BUNDLED_SIZES: VcSize[] = ["1k", "2k", "4k", "8k"];

  beforeAll(async () => {
    const wasmModule = await loadWasmModule();
    openac = await OpenAC.init({ assetsDir: ASSETS_DIR, wasmModule });
  });

  for (const size of BUNDLED_SIZES) {
    it(`returns a non-empty Uint8Array for size ${size}`, async () => {
      const vk = await openac.loadBundledShowVerifyingKey(size);
      expect(vk).toBeInstanceOf(Uint8Array);
      expect(vk.length).toBeGreaterThan(1_000_000); // ~3 MB
    });
  }

  it.skipIf(!HAS_LOCAL_1K)(
    "bundled show VK SHA-matches local ecdsa-spartan2 key",
    async () => {
      const bundled = await openac.loadBundledShowVerifyingKey("1k");
      const local = new Uint8Array(
        readFileSync(join(KEYS_DIR, "1k_show_verifying.key")),
      );
      expect(sha256Hex(bundled)).toBe(sha256Hex(local));
    },
  );
});

describe.skipIf(!HAS_LOCAL_1K)("OpenAC.loadKeys (in-memory)", () => {
  let openac: OpenAC;

  beforeAll(async () => {
    const wasmModule = await loadWasmModule();
    openac = await OpenAC.init({ assetsDir: ASSETS_DIR, wasmModule });
  });

  it("constructs a KeySet that round-trips through serialize()", async () => {
    const local = loadLocalKeySet("1k");
    const keys = await openac.loadKeys(local.serialize());

    expect(keys.prepareProvingKey).toBe(local.prepareProvingKey);
    expect(keys.prepareVerifyingKey).toBe(local.prepareVerifyingKey);
    expect(keys.showProvingKey).toBe(local.showProvingKey);
    expect(keys.showVerifyingKey).toBe(local.showVerifyingKey);

    const vks = keys.verifyingKeys();
    expect(vks.prepareVerifyingKey).toBe(local.prepareVerifyingKey);
    expect(vks.showVerifyingKey).toBe(local.showVerifyingKey);

    const re = keys.serialize();
    expect(re.prepareProvingKey).toBe(local.prepareProvingKey);
    expect(sha256Hex(re.showVerifyingKey)).toBe(sha256Hex(local.showVerifyingKey));
  });
});

describe.skipIf(!HAS_R2)("OpenAC.loadKeysFromUrl (R2)", () => {
  let openac: OpenAC;

  beforeAll(async () => {
    const wasmModule = await loadWasmModule();
    openac = await OpenAC.init({ assetsDir: ASSETS_DIR, wasmModule });
  });

  it("fetches a complete 1k key bundle via explicit baseUrl", async () => {
    const keys = await openac.loadKeysFromUrl("1k", R2_BASE_URL);
    expect(keys.prepareProvingKey.length).toBeGreaterThan(10_000_000);
    expect(keys.prepareVerifyingKey.length).toBeGreaterThan(10_000_000);
    expect(keys.showProvingKey.length).toBeGreaterThan(1_000_000);
    expect(keys.showVerifyingKey.length).toBeGreaterThan(1_000_000);
  }, 1_800_000);

  it.skipIf(!HAS_LOCAL_1K)(
    "remote keys SHA-match local source-of-truth keys",
    async () => {
      const keys = await openac.loadKeysFromUrl("1k", R2_BASE_URL);
      const localShowVk = new Uint8Array(
        readFileSync(join(KEYS_DIR, "1k_show_verifying.key")),
      );
      const localShowPk = new Uint8Array(
        readFileSync(join(KEYS_DIR, "1k_show_proving.key")),
      );
      expect(sha256Hex(keys.showVerifyingKey)).toBe(sha256Hex(localShowVk));
      expect(sha256Hex(keys.showProvingKey)).toBe(sha256Hex(localShowPk));
    },
    1_800_000,
  );

  it("uses keysBaseUrl from OpenACConfig when no URL arg passed", async () => {
    const wasmModule = await loadWasmModule();
    const configured = await OpenAC.init({
      assetsDir: ASSETS_DIR,
      wasmModule,
      keysBaseUrl: R2_BASE_URL,
    });
    const keys = await configured.loadKeysFromUrl("1k");
    expect(keys.showVerifyingKey.length).toBeGreaterThan(0);
  }, 1_800_000);

  it("rejects when a key file is missing from the bucket", async () => {
    await expect(
      openac.loadKeysFromUrl("1k", `${R2_BASE_URL}/nonexistent-prefix`),
    ).rejects.toThrow();
  }, 60_000);
});

describe.skipIf(!HAS_LOCAL_1K)("Typed predicate DSL", () => {
  let openac: OpenAC;

  beforeAll(async () => {
    const wasmModule = await loadWasmModule();
    openac = await OpenAC.init({ assetsDir: ASSETS_DIR, wasmModule });
  });

  it("proves a claim-to-claim predicate by claim name", async () => {
    const cred = makeDummy1k();
    const keys = loadLocalKeySet("1k");

    const precomputed = await openac.precompute({
      jwt: cred.jwt,
      disclosures: cred.disclosures,
      issuerPublicKey: cred.issuerPublicKey,
      keys,
      predicates: claimToClaimPredicate,
    });
    expect(precomputed.normalizedClaimValues.length).toBeGreaterThan(0);
    expect(precomputed.deviceKey.x).toBe(cred.devicePublicKey.x);

    const proof = await openac.present({
      precomputed,
      verifierNonce: "typed-dsl-c2c-nonce",
      devicePrivateKey: cred.devicePrivateKeyHex,
      issuerProof: issuerProofFor(cred.issuerPublicKey),
      revocation: revocationFor(cred),
      keys,
      predicates: claimToClaimPredicate,
    });

    const result = await openac.verify(
      proof,
      keys.verifyingKeys(),
      expectedStatement(cred, "typed-dsl-c2c-nonce", claimToClaimPredicate),
    );
    expect(result.valid).toBe(true);
    expect(result.expressionResult).toBe(true);
  }, 600_000);

  it("proves an age threshold with value: Date", async () => {
    const cred = makeDummy1k();
    const keys = loadLocalKeySet("1k");
    const cutoff = new Date(Date.UTC(2010, 0, 1));
    const predicate = {
      claim: "roc_birthday",
      op: "<=" as const,
      value: cutoff,
    };

    const precomputed = await openac.precompute({
      jwt: cred.jwt,
      disclosures: cred.disclosures,
      issuerPublicKey: cred.issuerPublicKey,
      keys,
      predicates: predicate,
    });

    const proof = await openac.present({
      precomputed,
      verifierNonce: "typed-dsl-age-nonce",
      devicePrivateKey: cred.devicePrivateKeyHex,
      issuerProof: issuerProofFor(cred.issuerPublicKey),
      revocation: revocationFor(cred),
      keys,
      predicates: predicate,
    });

    const result = await openac.verify(
      proof,
      keys.verifyingKeys(),
      expectedStatement(cred, "typed-dsl-age-nonce", predicate),
    );
    expect(result.valid).toBe(true);
    expect(result.expressionResult).toBe(true);
  }, 600_000);

  it("compiles `all` (AND) combinator into a single proof", async () => {
    const cred = makeDummy1k();
    const keys = loadLocalKeySet("1k");

    const expr = {
      all: [
        claimToClaimPredicate,
        { claim: "roc_birthday", op: "<=" as const, value: new Date(Date.UTC(2010, 0, 1)) },
      ],
    };

    const precomputed = await openac.precompute({
      jwt: cred.jwt,
      disclosures: cred.disclosures,
      issuerPublicKey: cred.issuerPublicKey,
      keys,
      predicates: expr,
    });

    const proof = await openac.present({
      precomputed,
      verifierNonce: "typed-dsl-all-nonce",
      devicePrivateKey: cred.devicePrivateKeyHex,
      issuerProof: issuerProofFor(cred.issuerPublicKey),
      revocation: revocationFor(cred),
      keys,
      predicates: expr,
    });

    const result = await openac.verify(
      proof,
      keys.verifyingKeys(),
      expectedStatement(cred, "typed-dsl-all-nonce", expr),
    );
    expect(result.valid).toBe(true);
    expect(result.expressionResult).toBe(true);
  }, 600_000);

  it("verifyComponents verifies pre-split proofs", async () => {
    const cred = makeDummy1k();
    const keys = loadLocalKeySet("1k");

    const precomputed = await openac.precompute({
      jwt: cred.jwt,
      disclosures: cred.disclosures,
      issuerPublicKey: cred.issuerPublicKey,
      keys,
      predicates: claimToClaimPredicate,
    });

    const proof = await openac.present({
      precomputed,
      verifierNonce: "verifyComponents-nonce",
      devicePrivateKey: cred.devicePrivateKeyHex,
      issuerProof: issuerProofFor(cred.issuerPublicKey),
      revocation: revocationFor(cred),
      keys,
      predicates: claimToClaimPredicate,
    });

    const result = await openac.verifyComponents(
      proof.prepareProof,
      proof.showProof,
      keys.verifyingKeys(),
      proof.prepareInstance,
      proof.showInstance,
      expectedStatement(cred, "verifyComponents-nonce", claimToClaimPredicate),
    );
    expect(result.valid).toBe(true);
  }, 600_000);

  it("verifyProof round-trips a serialized proof", async () => {
    const cred = makeDummy1k();
    const keys = loadLocalKeySet("1k");

    const precomputed = await openac.precompute({
      jwt: cred.jwt,
      disclosures: cred.disclosures,
      issuerPublicKey: cred.issuerPublicKey,
      keys,
      predicates: claimToClaimPredicate,
    });

    const proof = await openac.present({
      precomputed,
      verifierNonce: "verifyProof-nonce",
      devicePrivateKey: cred.devicePrivateKeyHex,
      issuerProof: issuerProofFor(cred.issuerPublicKey),
      revocation: revocationFor(cred),
      keys,
      predicates: claimToClaimPredicate,
    });

    const serialized = proof.serialize();
    expect(serialized.length).toBeGreaterThan(0);

    const result = await openac.verifyProof(
      serialized,
      keys.verifyingKeys(),
      expectedStatement(cred, "verifyProof-nonce", claimToClaimPredicate),
    );
    expect(result.valid).toBe(true);
  }, 600_000);

  it("rejects predicates referencing an unknown claim", async () => {
    const cred = makeDummy1k();
    const keys = loadLocalKeySet("1k");

    await expect(
      openac.precompute({
        jwt: cred.jwt,
        disclosures: cred.disclosures,
        issuerPublicKey: cred.issuerPublicKey,
        keys,
        predicates: { claim: "this_claim_does_not_exist", op: ">=", value: 1 },
      }),
    ).rejects.toThrow(/unknown claim/i);
  }, 60_000);

  // --- Statement-binding soundness (policy-swap + replay) ---
  //
  // A cryptographically valid Show proof only asserts "some hidden predicate
  // over the linked credential was true for some hidden nonce". These tests
  // prove the verifier now rejects unless that hidden statement equals its
  // expected nonce and policy.

  it("rejects a policy-swap: proof for an easy policy fails against the verifier's policy", async () => {
    const cred = makeDummy1k();
    const keys = loadLocalKeySet("1k");

    // Holder proves an easy policy that yields expressionResult === true...
    const easyPolicy: PredicateExpression = claimToClaimPredicate;
    // ...but the verifier requires a different (harder) policy.
    const verifierPolicy: PredicateExpression = {
      claim: "roc_birthday",
      op: ">=" as const,
      value: new Date(Date.UTC(2010, 0, 1)),
    };

    const precomputed = await openac.precompute({
      jwt: cred.jwt,
      disclosures: cred.disclosures,
      issuerPublicKey: cred.issuerPublicKey,
      keys,
      predicates: easyPolicy,
    });

    const proof = await openac.present({
      precomputed,
      verifierNonce: "policy-swap-nonce",
      devicePrivateKey: cred.devicePrivateKeyHex,
      issuerProof: issuerProofFor(cred.issuerPublicKey),
      revocation: revocationFor(cred),
      keys,
      predicates: easyPolicy,
    });

    // Sanity: the proof verifies against the policy it was actually made for.
    const honest = await openac.verify(
      proof,
      keys.verifyingKeys(),
      expectedStatement(cred, "policy-swap-nonce", easyPolicy),
    );
    expect(honest.valid).toBe(true);

    // Attack: same proof, same nonce, but the verifier's expected policy differs.
    const swapped = await openac.verify(
      proof,
      keys.verifyingKeys(),
      expectedStatement(cred, "policy-swap-nonce", verifierPolicy),
    );
    expect(swapped.valid).toBe(false);
    expect(swapped.expressionResult).toBeNull();
    expect(swapped.error).toMatch(/policy/i);
  }, 600_000);

  it("rejects a proof whose claims were normalized differently than the policy requires", async () => {
    const cred = makeDummy1k();
    const keys = loadLocalKeySet("1k");
    const nonce = "normalization-nonce";

    const precomputed = await openac.precompute({
      jwt: cred.jwt,
      disclosures: cred.disclosures,
      issuerPublicKey: cred.issuerPublicKey,
      keys,
      predicates: claimToClaimPredicate,
    });

    const proof = await openac.present({
      precomputed,
      verifierNonce: nonce,
      devicePrivateKey: cred.devicePrivateKeyHex,
      issuerProof: issuerProofFor(cred.issuerPublicKey),
      revocation: revocationFor(cred),
      keys,
      predicates: claimToClaimPredicate,
    });

    // Sanity: the proof verifies against the normalization it was built under.
    const honest = await openac.verify(
      proof,
      keys.verifyingKeys(),
      expectedStatement(cred, nonce, claimToClaimPredicate),
    );
    expect(honest.valid).toBe(true);

    // Same proof, same nonce, same predicate program, but the verifier requires
    // the claims to have been normalized as uint rather than as dates. The
    // normalization is in the Prepare proof's public IO, so the mismatch is
    // visible to the verifier.
    const base = expectedStatement(cred, nonce, claimToClaimPredicate);
    const mismatched = await openac.verify(proof, keys.verifyingKeys(), {
      ...base,
      claimNormalization: {
        decodeFlags: base.claimNormalization.decodeFlags,
        claimFormats: base.claimNormalization.claimFormats.map(() => 1),
      },
    });
    expect(mismatched.valid).toBe(false);
    expect(mismatched.expressionResult).toBeNull();
    expect(mismatched.error).toMatch(/normalization/i);

    // A policy reading a claim the proof never decoded is rejected too: that
    // claim's value is 0 rather than the credential's.
    const undecoded = await openac.verify(proof, keys.verifyingKeys(), {
      ...base,
      claimNormalization: {
        decodeFlags: base.claimNormalization.decodeFlags.map(() => 1),
        claimFormats: base.claimNormalization.claimFormats,
      },
    });
    if (base.claimNormalization.decodeFlags.some((f) => f !== 1)) {
      expect(undecoded.valid).toBe(false);
      expect(undecoded.error).toMatch(/undecoded/i);
    }
  }, 600_000);

  it("hides the issuer: reports only the registry root, which the verifier accepts", async () => {
    const cred = makeDummy1k();
    const other = generateDummyCredential({
      size: "1k",
      issuerPrivateKey: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
      revocationSecret: "1111111111111111111111111111111111111111111111111111111111111111",
      claims: [
        { key: "roc_birthday", value: "0900101" },
        { key: "roc_max", value: "0950101" },
      ],
    });
    const keys = loadLocalKeySet("1k");
    const registry = createIssuerRegistry([other.issuerPublicKey, cred.issuerPublicKey]);

    const precomputed = await openac.precompute({
      jwt: cred.jwt,
      disclosures: cred.disclosures,
      issuerPublicKey: cred.issuerPublicKey,
      keys,
      predicates: claimToClaimPredicate,
    });
    const proof = await openac.present({
      precomputed,
      verifierNonce: "issuer-hiding-nonce-001",
      devicePrivateKey: cred.devicePrivateKeyHex,
      issuerProof: registry.generateProof(issuerCommitment(cred.issuerPublicKey)),
      revocation: revocationFor(cred),
      keys,
      predicates: claimToClaimPredicate,
    });

    const result = await openac.verify(proof, keys.verifyingKeys(), {
      ...expectedStatement(cred, "issuer-hiding-nonce-001", claimToClaimPredicate),
      isValidIssuerRoot: (root) => root === registry.root,
    });
    expect(result.valid).toBe(true);
    expect(result.issuerRoot).toBe(registry.root);
    expect(result.revocationRoot).toBe(REGISTRY.root);

    // A credential from the other issuer exposes the same issuer root and the
    // same revocation root: revocation uses one registry for all issuers, so
    // neither public root tells the two issuers apart.
    const otherProof = await openac.present({
      precomputed: await openac.precompute({
        jwt: other.jwt,
        disclosures: other.disclosures,
        issuerPublicKey: other.issuerPublicKey,
        keys,
        predicates: claimToClaimPredicate,
      }),
      verifierNonce: "issuer-hiding-nonce-001",
      devicePrivateKey: other.devicePrivateKeyHex,
      issuerProof: registry.generateProof(issuerCommitment(other.issuerPublicKey)),
      revocation: revocationFor(other),
      keys,
      predicates: claimToClaimPredicate,
    });
    const otherResult = await openac.verify(otherProof, keys.verifyingKeys(), {
      ...expectedStatement(other, "issuer-hiding-nonce-001", claimToClaimPredicate),
      isValidIssuerRoot: (root) => root === registry.root,
    });
    expect(otherResult.valid).toBe(true);
    expect(otherResult.issuerRoot).toBe(result.issuerRoot);
    expect(otherResult.revocationRoot).toBe(result.revocationRoot);
  }, 1_200_000);

  it("rejects a credential from an issuer outside the accepted registry", async () => {
    const keys = loadLocalKeySet("1k");
    const accepted = createIssuerRegistry([makeDummy1k().issuerPublicKey]);
    // Self-signed credential: the holder can only build a registry of their own key.
    const forged = generateDummyCredential({
      size: "1k",
      issuerPrivateKey: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
      claims: [
        { key: "roc_birthday", value: "0900101" },
        { key: "roc_max", value: "0950101" },
      ],
    });

    const precomputed = await openac.precompute({
      jwt: forged.jwt,
      disclosures: forged.disclosures,
      issuerPublicKey: forged.issuerPublicKey,
      keys,
      predicates: claimToClaimPredicate,
    });

    // A proof from the accepted registry is for another issuer, so present() refuses it.
    await expect(
      openac.present({
        precomputed,
        verifierNonce: "issuer-hiding-nonce-002",
        devicePrivateKey: forged.devicePrivateKeyHex,
        issuerProof: accepted.generateProof(accepted.commitments[0]!),
        revocation: revocationFor(forged),
        keys,
        predicates: claimToClaimPredicate,
      }),
    ).rejects.toThrow(/issuer/i);

    const proof = await openac.present({
      precomputed,
      verifierNonce: "issuer-hiding-nonce-002",
      devicePrivateKey: forged.devicePrivateKeyHex,
      issuerProof: issuerProofFor(forged.issuerPublicKey),
      revocation: revocationFor(forged),
      keys,
      predicates: claimToClaimPredicate,
    });
    const result = await openac.verify(proof, keys.verifyingKeys(), {
      ...expectedStatement(forged, "issuer-hiding-nonce-002", claimToClaimPredicate),
      isValidIssuerRoot: (root) => root === accepted.root,
    });
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/issuer root/i);
  }, 600_000);

  it("rejects a replay: proof for an old nonce fails against a fresh challenge", async () => {
    const cred = makeDummy1k();
    const keys = loadLocalKeySet("1k");

    const precomputed = await openac.precompute({
      jwt: cred.jwt,
      disclosures: cred.disclosures,
      issuerPublicKey: cred.issuerPublicKey,
      keys,
      predicates: claimToClaimPredicate,
    });

    const proof = await openac.present({
      precomputed,
      verifierNonce: "captured-old-nonce",
      devicePrivateKey: cred.devicePrivateKeyHex,
      issuerProof: issuerProofFor(cred.issuerPublicKey),
      revocation: revocationFor(cred),
      keys,
      predicates: claimToClaimPredicate,
    });

    // Replayed against a different (fresh) session challenge.
    const replayed = await openac.verify(
      proof,
      keys.verifyingKeys(),
      expectedStatement(cred, "fresh-session-nonce", claimToClaimPredicate),
    );
    expect(replayed.valid).toBe(false);
    expect(replayed.expressionResult).toBeNull();
    expect(replayed.error).toMatch(/nonce/i);
  }, 600_000);

  it("proves non-revocation against the registry root and rejects an unaccepted root", async () => {
    const cred = makeDummy1k();
    const keys = loadLocalKeySet("1k");
    const nonce = "revocation-root-nonce";

    const precomputed = await openac.precompute({
      jwt: cred.jwt,
      disclosures: cred.disclosures,
      issuerPublicKey: cred.issuerPublicKey,
      keys,
      predicates: claimToClaimPredicate,
    });
    const proof = await openac.present({
      precomputed,
      verifierNonce: nonce,
      devicePrivateKey: cred.devicePrivateKeyHex,
      issuerProof: issuerProofFor(cred.issuerPublicKey),
      revocation: revocationFor(cred),
      keys,
      predicates: claimToClaimPredicate,
    });
    expect(proof.publicValues.revocationRoot).toBe(REGISTRY.root);

    const expected = expectedStatement(cred, nonce, claimToClaimPredicate);
    const accepted = await openac.verify(proof, keys.verifyingKeys(), expected);
    expect(accepted.valid).toBe(true);
    expect(accepted.revocationRoot).toBe(REGISTRY.root);

    // A verifier whose registry has moved on rejects the stale root.
    const stale = await openac.verify(proof, keys.verifyingKeys(), {
      ...expected,
      isValidRevocationRoot: acceptRevocationRoots([REGISTRY.root + 1n]),
    });
    expect(stale.valid).toBe(false);
    expect(stale.error).toMatch(/Revocation root/);
  }, 600_000);

  it("proves against an empty registry with root 0", async () => {
    const cred = makeDummy1k();
    const keys = loadLocalKeySet("1k");
    const nonce = "revocation-empty-nonce";

    const precomputed = await openac.precompute({
      jwt: cred.jwt,
      disclosures: cred.disclosures,
      issuerPublicKey: cred.issuerPublicKey,
      keys,
      predicates: claimToClaimPredicate,
    });
    const proof = await openac.present({
      precomputed,
      verifierNonce: nonce,
      devicePrivateKey: cred.devicePrivateKeyHex,
      issuerProof: issuerProofFor(cred.issuerPublicKey),
      revocation: { secret: cred.revocationSecretHex, registry: createRevocationRegistry() },
      keys,
      predicates: claimToClaimPredicate,
    });

    const result = await openac.verify(proof, keys.verifyingKeys(), {
      ...expectedStatement(cred, nonce, claimToClaimPredicate),
      isValidRevocationRoot: acceptRevocationRoots([0n]),
    });
    expect(result.valid).toBe(true);
    expect(result.revocationRoot).toBe(0n);
  }, 600_000);

  it("refuses to present a revoked credential", async () => {
    const cred = makeDummy1k();
    const keys = loadLocalKeySet("1k");
    const registry = createRevocationRegistry([...REGISTRY.commitments, cred.revocationCommitment]);

    const precomputed = await openac.precompute({
      jwt: cred.jwt,
      disclosures: cred.disclosures,
      issuerPublicKey: cred.issuerPublicKey,
      keys,
      predicates: claimToClaimPredicate,
    });

    await expect(
      openac.present({
        precomputed,
        verifierNonce: "revoked-credential-nonce",
        devicePrivateKey: cred.devicePrivateKeyHex,
        issuerProof: issuerProofFor(cred.issuerPublicKey),
        revocation: { secret: cred.revocationSecretHex, registry },
        keys,
        predicates: claimToClaimPredicate,
      }),
    ).rejects.toMatchObject({ code: "CREDENTIAL_REVOKED" });
  }, 600_000);
});

describe.skipIf(!HAS_R2)("Full pipeline with keys fetched from R2", () => {
  it("end-to-end via loadKeysFromUrl and typed predicates", async () => {
    const wasmModule = await loadWasmModule();
    const openac = await OpenAC.init({
      assetsDir: ASSETS_DIR,
      wasmModule,
      keysBaseUrl: R2_BASE_URL,
    });

    const cred = makeDummy1k();
    const keys = await openac.loadKeysFromUrl("1k");

    const precomputed = await openac.precompute({
      jwt: cred.jwt,
      disclosures: cred.disclosures,
      issuerPublicKey: cred.issuerPublicKey,
      keys,
      predicates: claimToClaimPredicate,
    });

    const proof = await openac.present({
      precomputed,
      verifierNonce: "sdk-e2e-r2-nonce",
      devicePrivateKey: cred.devicePrivateKeyHex,
      issuerProof: issuerProofFor(cred.issuerPublicKey),
      revocation: revocationFor(cred),
      keys,
      predicates: claimToClaimPredicate,
    });

    const result = await openac.verify(
      proof,
      keys.verifyingKeys(),
      expectedStatement(cred, "sdk-e2e-r2-nonce", claimToClaimPredicate),
    );
    expect(result.valid).toBe(true);
    expect(result.expressionResult).toBe(true);
  }, 2_400_000);

  it("verifies with bundled show VK + remote prepare VK (hybrid offline-friendly)", async () => {
    const wasmModule = await loadWasmModule();
    const openac = await OpenAC.init({ assetsDir: ASSETS_DIR, wasmModule });

    const cred = makeDummy1k();
    const keys = await openac.loadKeysFromUrl("1k", R2_BASE_URL);
    const bundledShowVk = await openac.loadBundledShowVerifyingKey("1k");

    const precomputed = await openac.precompute({
      jwt: cred.jwt,
      disclosures: cred.disclosures,
      issuerPublicKey: cred.issuerPublicKey,
      keys,
      predicates: claimToClaimPredicate,
    });

    const proof = await openac.present({
      precomputed,
      verifierNonce: "sdk-e2e-hybrid-nonce",
      devicePrivateKey: cred.devicePrivateKeyHex,
      issuerProof: issuerProofFor(cred.issuerPublicKey),
      revocation: revocationFor(cred),
      keys,
      predicates: claimToClaimPredicate,
    });

    expect(sha256Hex(bundledShowVk)).toBe(sha256Hex(keys.showVerifyingKey));
    const result = await openac.verify(
      proof,
      {
        prepareVerifyingKey: keys.prepareVerifyingKey,
        showVerifyingKey: bundledShowVk,
      },
      expectedStatement(cred, "sdk-e2e-hybrid-nonce", claimToClaimPredicate),
    );
    expect(result.valid).toBe(true);
  }, 2_400_000);
});

describe("SDK e2e test configuration", () => {
  it("reports active modes", () => {
    const modes: string[] = [];
    if (HAS_LOCAL_1K) modes.push("local-1k");
    if (HAS_LOCAL_2K) modes.push("local-2k");
    if (HAS_R2) modes.push(`remote (${R2_BASE_URL})`);
    if (modes.length === 0) {
      modes.push(
        "none: provide local keys in ../ecdsa-spartan2/keys/ or set OPENAC_KEYS_URL",
      );
    }
    expect(modes.length).toBeGreaterThan(0);
    // eslint-disable-next-line no-console
    console.log(`[sdk-e2e] active modes: ${modes.join(", ")}`);
  });
});
