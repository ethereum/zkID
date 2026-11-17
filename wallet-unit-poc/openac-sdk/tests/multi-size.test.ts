import { describe, it, expect, beforeAll } from "vitest";
import { existsSync, readFileSync } from "fs";
import { readFile } from "fs/promises";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

import {
  OpenAC,
  Credential,
  compilePredicateExpression,
  requiredNormalization,
} from "../src/index.js";
import { generateDummyCredential, issuerProofFor } from "../src/testing/index.js";
import type { VcSize } from "../src/sizing.js";
import type { KeySet, VerifyingKeys } from "../src/types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const KEYS_DIR = join(__dirname, "..", "..", "ecdsa-spartan2", "keys");
const ASSETS_DIR = join(__dirname, "..", "assets");
const WASM_PKG_DIR = join(__dirname, "..", "wasm", "pkg");

async function loadWasmModule() {
  const mod = await import(/* webpackIgnore: true */ join(WASM_PKG_DIR, "openac_wasm.js"));
  const bin = await readFile(join(WASM_PKG_DIR, "openac_wasm_bg.wasm"));
  mod.initSync({ module: bin });
  return mod;
}

function keyFilenames(size: VcSize): string[] {
  return [
    `${size}_prepare_proving.key`,
    `${size}_prepare_verifying.key`,
    `${size}_show_proving.key`,
    `${size}_show_verifying.key`,
  ];
}

function hasKeysFor(size: VcSize): boolean {
  return keyFilenames(size).every((f) => existsSync(join(KEYS_DIR, f)));
}

function loadKeys(size: VcSize): KeySet {
  const [pp, pv, sp, sv] = keyFilenames(size);
  const prepareProvingKey = new Uint8Array(readFileSync(join(KEYS_DIR, pp)));
  const prepareVerifyingKey = new Uint8Array(readFileSync(join(KEYS_DIR, pv)));
  const showProvingKey = new Uint8Array(readFileSync(join(KEYS_DIR, sp)));
  const showVerifyingKey = new Uint8Array(readFileSync(join(KEYS_DIR, sv)));
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

const SIZES: VcSize[] = ["1k", "2k", "4k", "8k"];
// 4k/8k PKs exceed WASM's 32-bit address space; use NativeBackend for those.
const WASM_PROVABLE: VcSize[] = ["1k", "2k"];

const claimToClaimPredicate = {
  claim: "roc_birthday",
  op: "<=" as const,
  compareTo: { claim: "roc_max" },
};

describe("multi-size pipeline", () => {
  for (const size of SIZES) {
    const skip = !hasKeysFor(size) || !WASM_PROVABLE.includes(size);
    describe.skipIf(skip)(`circuit slot ${size}`, () => {
      let openac: OpenAC;

      beforeAll(async () => {
        const wasmModule = await loadWasmModule();
        openac = await OpenAC.init({ assetsDir: ASSETS_DIR, wasmModule });
      });

      it("proves + verifies a claim-to-claim predicate", async () => {
        const cred = generateDummyCredential({
          size,
          claims: [
            { key: "roc_birthday", value: "0900101" },
            { key: "roc_max", value: "0950101" },
          ],
        });

        const keys = loadKeys(size);

        const precomputed = await openac.precompute({
          jwt: cred.jwt,
          disclosures: cred.disclosures,
          issuerPublicKey: cred.issuerPublicKey,
          keys,
          predicates: claimToClaimPredicate,
        });

        const nonce = `verifier-nonce-mul-${size}`;
        const proof = await openac.present({
          precomputed,
          verifierNonce: nonce,
          devicePrivateKey: cred.devicePrivateKeyHex,
          issuerProof: issuerProofFor(cred.issuerPublicKey),
          keys,
          predicates: claimToClaimPredicate,
        });

        const schema = Credential.parse(cred.jwt, cred.disclosures).claims;
        const compiled = compilePredicateExpression(claimToClaimPredicate, schema);
        const verification = await openac.verify(proof, keys.verifyingKeys(), {
          nonce,
          predicates: compiled.predicates,
          logicExpression: compiled.logicExpression,
          claimNormalization: requiredNormalization(compiled),
        });

        expect(verification.valid).toBe(true);
        expect(verification.expressionResult).toBe(true);
      }, 600_000);
    });
  }
});
