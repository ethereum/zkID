import { describe, it, expect, beforeAll } from "vitest";
import { readFile } from "fs/promises";
import { existsSync, readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

import {
  OpenAC,
  Verifier,
  Credential,
  compilePredicateExpression,
  requiredNormalization,
  acceptRevocationRoots,
  createRevocationRegistry,
} from "../src/index.js";
import { WasmBridge } from "../src/wasm-bridge.js";
import { generateDummyCredential } from "../src/testing/index.js";
import type {
  VerifyingKeys,
  KeySet,
  ExpectedStatement,
  PresentationProof,
} from "../src/types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const KEYS_DIR = join(__dirname, "..", "..", "ecdsa-spartan2", "keys");
const ASSETS_DIR = join(__dirname, "..", "assets");
const WASM_PKG_DIR = join(__dirname, "..", "wasm", "pkg");

const HAS_1K_KEYS =
  existsSync(join(KEYS_DIR, "1k_show_proving.key")) &&
  existsSync(join(WASM_PKG_DIR, "openac_wasm.js"));

const claimToClaimPredicate = {
  claim: "roc_birthday",
  op: "<=" as const,
  compareTo: { claim: "roc_max" },
};

function loadLocalKeySet(size: string): KeySet {
  const prepareProvingKey = new Uint8Array(readFileSync(join(KEYS_DIR, `${size}_prepare_proving.key`)));
  const prepareVerifyingKey = new Uint8Array(readFileSync(join(KEYS_DIR, `${size}_prepare_verifying.key`)));
  const showProvingKey = new Uint8Array(readFileSync(join(KEYS_DIR, `${size}_show_proving.key`)));
  const showVerifyingKey = new Uint8Array(readFileSync(join(KEYS_DIR, `${size}_show_verifying.key`)));
  return {
    prepareProvingKey,
    prepareVerifyingKey,
    showProvingKey,
    showVerifyingKey,
    verifyingKeys: () => ({ prepareVerifyingKey, showVerifyingKey }),
    serialize: () => ({ prepareProvingKey, prepareVerifyingKey, showProvingKey, showVerifyingKey }),
  };
}

describe.skipIf(!HAS_1K_KEYS)("WASM Verifier: Artifact Availability", () => {
  it("should have WASM module built", () => {
    expect(existsSync(join(WASM_PKG_DIR, "openac_wasm.js"))).toBe(true);
    expect(existsSync(join(WASM_PKG_DIR, "openac_wasm_bg.wasm"))).toBe(true);
  });

  it("should have verifying keys generated", () => {
    expect(existsSync(join(KEYS_DIR, "1k_prepare_verifying.key"))).toBe(true);
    expect(existsSync(join(KEYS_DIR, "1k_show_verifying.key"))).toBe(true);
  });
});

describe("WASM Verifier: Class Structure", () => {
  it("should instantiate Verifier with WasmBridge", () => {
    const bridge = new WasmBridge();
    const verifier = new Verifier(bridge);
    expect(verifier).toBeInstanceOf(Verifier);
  });

  it("should have verifyProof method", () => {
    const bridge = new WasmBridge();
    const verifier = new Verifier(bridge);
    expect(typeof verifier.verifyProof).toBe("function");
  });

  it("should have verifyComponents method", () => {
    const bridge = new WasmBridge();
    const verifier = new Verifier(bridge);
    expect(typeof verifier.verifyComponents).toBe("function");
  });
});

describe.skipIf(!HAS_1K_KEYS)("WASM Verifier: WasmBridge Initialization", () => {
  it("should load WASM module synchronously", async () => {
    const bridge = new WasmBridge();
    expect(bridge.isInitialized).toBe(false);

    const wasmModule = await import(
      /* webpackIgnore: true */ join(WASM_PKG_DIR, "openac_wasm.js")
    );
    const wasmBinary = await readFile(join(WASM_PKG_DIR, "openac_wasm_bg.wasm"));
    wasmModule.initSync({ module: wasmBinary });
    bridge.initWithModule(wasmModule);

    expect(bridge.isInitialized).toBe(true);
  });
});

// Verifier-class tests operate on a freshly generated 1k proof (known nonce +
// policy + claims), so they exercise the statement-binding path end-to-end
// rather than depending on committed proof fixtures that go stale whenever the
// circuit or keys change.
describe.skipIf(!HAS_1K_KEYS)("WASM Verifier: proof verification via Verifier class", () => {
  let verifier: Verifier;
  let verifyingKeys: VerifyingKeys;
  let proof: PresentationProof;
  let expected: ExpectedStatement;
  let ready = false;

  beforeAll(async () => {
    const wasmModule = await import(
      /* webpackIgnore: true */ join(WASM_PKG_DIR, "openac_wasm.js")
    );
    const wasmBinary = await readFile(join(WASM_PKG_DIR, "openac_wasm_bg.wasm"));
    wasmModule.initSync({ module: wasmBinary });

    const openac = await OpenAC.init({ assetsDir: ASSETS_DIR, wasmModule });
    const keys = loadLocalKeySet("1k");
    verifyingKeys = keys.verifyingKeys();

    const cred = generateDummyCredential({
      size: "1k",
      claims: [
        { key: "roc_birthday", value: "0900101" },
        { key: "roc_max", value: "0950101" },
      ],
    });
    const nonce = "wasm-verifier-nonce";

    const precomputed = await openac.precompute({
      jwt: cred.jwt,
      disclosures: cred.disclosures,
      issuerPublicKey: cred.issuerPublicKey,
      keys,
      predicates: claimToClaimPredicate,
    });
    proof = await openac.present({
      precomputed,
      verifierNonce: nonce,
      devicePrivateKey: cred.devicePrivateKeyHex,
      revocation: { secret: cred.revocationSecretHex, registry: createRevocationRegistry() },
      keys,
      predicates: claimToClaimPredicate,
    });

    const schema = Credential.parse(cred.jwt, cred.disclosures).claims;
    const compiled = compilePredicateExpression(claimToClaimPredicate, schema);
    expected = {
      nonce,
      predicates: compiled.predicates,
      logicExpression: compiled.logicExpression,
      claimNormalization: requiredNormalization(compiled),
      isValidRevocationRoot: acceptRevocationRoots([0n]),
    };

    // The Verifier class is exercised directly (not via OpenAC) on a bridge
    // sharing the same WASM module instance.
    const bridge = new WasmBridge();
    bridge.initWithModule(wasmModule);
    verifier = new Verifier(bridge);
    ready = true;
  }, 600_000);

  it("verifies a valid proof against its expected statement", async () => {
    if (!ready) return;
    const result = await verifier.verifyComponents(
      proof.prepareProof,
      proof.showProof,
      verifyingKeys,
      proof.prepareInstance,
      proof.showInstance,
      expected,
    );
    expect(result.valid).toBe(true);
    expect(result.error).toBeUndefined();
    expect(typeof result.expressionResult).toBe("boolean");
    expect(result.verifyMs).toBeGreaterThan(0);
  }, 60_000);

  it("rejects a proof with corrupted bytes", async () => {
    if (!ready) return;
    const corruptedProof = new Uint8Array(proof.prepareProof.slice());
    corruptedProof[Math.floor(corruptedProof.length / 2)] ^= 0xff;

    const result = await verifier.verifyComponents(
      corruptedProof,
      proof.showProof,
      verifyingKeys,
      proof.prepareInstance,
      proof.showInstance,
      expected,
    );
    expect(result.valid).toBe(false);
  }, 60_000);

  it("rejects a proof verified with the wrong verifying key", async () => {
    if (!ready) return;
    const wrongKeys: VerifyingKeys = {
      prepareVerifyingKey: verifyingKeys.showVerifyingKey,
      showVerifyingKey: verifyingKeys.prepareVerifyingKey,
    };

    const result = await verifier.verifyComponents(
      proof.prepareProof,
      proof.showProof,
      wrongKeys,
      proof.prepareInstance,
      proof.showInstance,
      expected,
    );
    expect(result.valid).toBe(false);
  }, 60_000);

  it("rejects a valid proof against a mismatched expected statement", async () => {
    if (!ready) return;
    const result = await verifier.verifyComponents(
      proof.prepareProof,
      proof.showProof,
      verifyingKeys,
      proof.prepareInstance,
      proof.showInstance,
      { ...expected, nonce: "a-different-nonce" },
    );
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/nonce/i);
  }, 60_000);
});

