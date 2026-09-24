// Async loader and typed wrapper over the Spartan2 WASM module.
// Provides high-level API methods aligned with the zkID paper protocol:
// 1. loadKeys(baseUrl, vcSize)    Fetch pre-generated keys (one-time, by VC size)
// 2. precomputeFromWitness()      Prove Prepare circuit (once per credential)
// 3. precomputeShowFromWitness()  Prove Show circuit (once per credential)
// 4. present()                    Reblind both proofs with shared randomness (per presentation)
// 5. verify()                     Verify both proofs + commitment check (per presentation)
//
// NOTE: Keys are generated offline via native CLI, not in browser.

import { WasmError } from "./errors.js";
import type { VcSize } from "./sizing.js";

export type { VcSize } from "./sizing.js";

// Pinned SHA-256 digests of the canonical OpenAC setup keys (matches the key
// set in ecdsa-spartan2/keys/ and the bundled assets). The key CDN is NOT
// trusted: any fetched key that does not match its pinned digest is rejected,
// so a compromised distribution path cannot substitute attacker parameters.
// Regenerate with: shasum -a 256 ecdsa-spartan2/keys/*_{proving,verifying}.key
const KEY_SHA256: Record<string, string> = {
  "1k_prepare_proving.key":
    "095f9c253274a831eb5d8225b6d7b855ab8471621968e773c041c83f32c46e8a",
  "1k_prepare_verifying.key":
    "f1fcc1d5036ef6ca9efb538b3510a5a492518018beb217c50ee2c014d7351add",
  "1k_show_proving.key":
    "809f24ca6ee003b684e2282b77f5a47279528edee7654a3801770a2ffca67831",
  "1k_show_verifying.key":
    "f0c447a9757d182e8aa23083bc3dba5a9a22f3e0fcbb344724568cc3c83352d8",
  "2k_prepare_proving.key":
    "853657d2e701215a65c5d97ab3cf5640e9aa8379ac6d106b7c82dc9b9d078e79",
  "2k_prepare_verifying.key":
    "9b45cc7462a236b1056d21c19e1e4dfc2cf52fd20538d43fbe072d9ed106e9d6",
  "2k_show_proving.key":
    "809f24ca6ee003b684e2282b77f5a47279528edee7654a3801770a2ffca67831",
  "2k_show_verifying.key":
    "f0c447a9757d182e8aa23083bc3dba5a9a22f3e0fcbb344724568cc3c83352d8",
  "4k_prepare_proving.key":
    "cd7aa960798ec7da3ee7e6e7dd582939a35a17128aa5c836325ea85c143e6ab7",
  "4k_prepare_verifying.key":
    "530affa94322388b39e88151acf2a6919fdd267356f6da48ed920f23cd30641c",
  "4k_show_proving.key":
    "809f24ca6ee003b684e2282b77f5a47279528edee7654a3801770a2ffca67831",
  "4k_show_verifying.key":
    "f0c447a9757d182e8aa23083bc3dba5a9a22f3e0fcbb344724568cc3c83352d8",
  "8k_prepare_proving.key":
    "21f69742f1e890f1ecde58e244d2afec4806d2e6aa2f42d76fa0c8a5738dd7d6",
  "8k_prepare_verifying.key":
    "af9a706b66e726d66cc88032f040ae133df8031437d3bda4077056fdca22a1a5",
  "8k_show_proving.key":
    "809f24ca6ee003b684e2282b77f5a47279528edee7654a3801770a2ffca67831",
  "8k_show_verifying.key":
    "f0c447a9757d182e8aa23083bc3dba5a9a22f3e0fcbb344724568cc3c83352d8",
};

async function verifyKeyDigest(
  filename: string,
  bytes: Uint8Array,
  url: string,
): Promise<void> {
  const expected = KEY_SHA256[filename];
  if (!expected) {
    throw new WasmError(
      "KEY_INTEGRITY_FAILED",
      `No pinned digest for key file ${filename}; refusing to load it.`,
    );
  }
  const digest = new Uint8Array(
    await globalThis.crypto.subtle.digest("SHA-256", bytes),
  );
  const actual = Array.from(digest)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  if (actual !== expected) {
    throw new WasmError(
      "KEY_INTEGRITY_FAILED",
      `Key ${filename} from ${url} failed integrity check: expected sha256 ${expected}, got ${actual}.`,
    );
  }
}

interface WasmPrecomputeResult {
  proof: Uint8Array;
  instance: Uint8Array;
  witness: Uint8Array;
}

interface WasmPresentResult {
  prepare_proof: Uint8Array;
  prepare_instance: Uint8Array;
  show_proof: Uint8Array;
  show_instance: Uint8Array;
}

interface WasmVerifyResult {
  valid: boolean;
  prepare_public_values: string[];
  show_public_values: string[];
  error: string | null;
}

interface OpenACWasmModule {
  init(): void;
  precompute_from_witness(
    pk: Uint8Array,
    witnessWtns: Uint8Array,
    vcSize: VcSize,
  ): WasmPrecomputeResult;
  precompute_show_from_witness(
    pk: Uint8Array,
    witnessWtns: Uint8Array,
  ): WasmPrecomputeResult;
  present(
    preparePk: Uint8Array,
    prepareInstance: Uint8Array,
    prepareWitness: Uint8Array,
    showPk: Uint8Array,
    showInstance: Uint8Array,
    showWitness: Uint8Array,
  ): WasmPresentResult;
  verify(
    prepareProof: Uint8Array,
    prepareVk: Uint8Array,
    prepareInstance: Uint8Array,
    showProof: Uint8Array,
    showVk: Uint8Array,
    showInstance: Uint8Array,
  ): WasmVerifyResult;
}

export interface SetupKeys {
  preparePk: Uint8Array;
  prepareVk: Uint8Array;
  showPk: Uint8Array;
  showVk: Uint8Array;
}

export interface PrecomputeState {
  proof: Uint8Array;
  instance: Uint8Array;
  witness: Uint8Array;
}

export interface PresentationProof {
  prepareProof: Uint8Array;
  prepareInstance: Uint8Array;
  showProof: Uint8Array;
  showInstance: Uint8Array;
}

export interface VerificationResult {
  valid: boolean;
  /** Prepare public IO: [pubKeyX, pubKeyY, decodeFlags[n], claimFormats[n]]. */
  preparePublicValues: string[];
  showPublicValues: string[];
  error?: string;
}

export class WasmBridge {
  private wasm: OpenACWasmModule | null = null;
  private initialized = false;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  initWithModule(module: any): void {
    if (this.initialized) return;
    this.wasm = module as OpenACWasmModule;
    if (this.wasm?.init) {
      this.wasm.init();
    }
    this.initialized = true;
  }

  async init(wasmPath?: string): Promise<void> {
    if (this.initialized) return;

    if (wasmPath) {
      const module = await import(/* webpackIgnore: true */ wasmPath);
      this.wasm = module as OpenACWasmModule;
    } else {
      try {
        // The wasm/pkg/openac_wasm.js module is generated at build time by
        // `pnpm build:wasm` (wasm-pack output, --target web). In Node the
        // wasm binary must be loaded explicitly; browsers auto-fetch via the
        // module's default export.
        // @ts-ignore wasm-pack output is generated at runtime by build:wasm
        const module = await import("../wasm/pkg/openac_wasm.js");
        const isNode = typeof process !== "undefined" && !!process.versions?.node;
        if (isNode && typeof module.initSync === "function") {
          const { readFile } = await import("fs/promises");
          const { fileURLToPath } = await import("url");
          const { dirname, join } = await import("path");
          const here = dirname(fileURLToPath(import.meta.url));
          const wasmBytes = await readFile(
            join(here, "..", "wasm", "pkg", "openac_wasm_bg.wasm"),
          );
          module.initSync({ module: wasmBytes });
        }
        this.wasm = module as OpenACWasmModule;
      } catch (e) {
        throw new WasmError(
          "WASM_LOAD_FAILED",
          `Could not load bundled WASM module: ${e instanceof Error ? e.message : String(e)}. Build it first (pnpm build:wasm) or provide wasmPath/wasmModule.`,
        );
      }
    }

    if (this.wasm?.init) {
      this.wasm.init();
    }

    this.initialized = true;
  }

  get isInitialized(): boolean {
    return this.initialized;
  }

  private getWasm(): OpenACWasmModule {
    if (!this.wasm || !this.initialized) {
      throw new WasmError(
        "WASM_NOT_INITIALIZED",
        "WASM module not initialized. Call init() first.",
      );
    }
    return this.wasm;
  }

  async loadKeys(baseUrl: string, vcSize: VcSize): Promise<SetupKeys> {
    const prefix = `${vcSize}_`;
    const keyFiles = [
      `${prefix}prepare_proving.key`,
      `${prefix}prepare_verifying.key`,
      `${prefix}show_proving.key`,
      `${prefix}show_verifying.key`,
    ];

    const fetchKey = async (filename: string): Promise<Uint8Array> => {
      const url = `${baseUrl}/${filename}`;
      const response = await fetch(url);
      if (!response.ok) {
        throw new WasmError(
          "KEY_LOAD_FAILED",
          `Failed to load key from ${url}: ${response.status} ${response.statusText}`,
        );
      }
      const buffer = await response.arrayBuffer();
      const bytes = new Uint8Array(buffer);
      await verifyKeyDigest(filename, bytes, url);
      return bytes;
    };

    const keys = await Promise.all(keyFiles.map(fetchKey));
    const [preparePk, prepareVk, showPk, showVk] = keys as [
      Uint8Array,
      Uint8Array,
      Uint8Array,
      Uint8Array,
    ];

    return { preparePk, prepareVk, showPk, showVk };
  }

  async precomputeFromWitness(
    preparePk: Uint8Array,
    witnessWtns: Uint8Array,
    vcSize: VcSize,
  ): Promise<PrecomputeState> {
    const wasm = this.getWasm();
    const result = wasm.precompute_from_witness(preparePk, witnessWtns, vcSize);
    return {
      proof: new Uint8Array(result.proof),
      instance: new Uint8Array(result.instance),
      witness: new Uint8Array(result.witness),
    };
  }

  async precomputeShowFromWitness(
    showPk: Uint8Array,
    witnessWtns: Uint8Array,
  ): Promise<PrecomputeState> {
    const wasm = this.getWasm();
    const result = wasm.precompute_show_from_witness(showPk, witnessWtns);
    return {
      proof: new Uint8Array(result.proof),
      instance: new Uint8Array(result.instance),
      witness: new Uint8Array(result.witness),
    };
  }

  async present(
    preparePk: Uint8Array,
    prepareInstance: Uint8Array,
    prepareWitness: Uint8Array,
    showPk: Uint8Array,
    showInstance: Uint8Array,
    showWitness: Uint8Array,
  ): Promise<PresentationProof> {
    const wasm = this.getWasm();
    const result = wasm.present(
      preparePk,
      prepareInstance,
      prepareWitness,
      showPk,
      showInstance,
      showWitness,
    );
    return {
      prepareProof: new Uint8Array(result.prepare_proof),
      prepareInstance: new Uint8Array(result.prepare_instance),
      showProof: new Uint8Array(result.show_proof),
      showInstance: new Uint8Array(result.show_instance),
    };
  }

  async verify(
    prepareProof: Uint8Array,
    prepareVk: Uint8Array,
    prepareInstance: Uint8Array,
    showProof: Uint8Array,
    showVk: Uint8Array,
    showInstance: Uint8Array,
  ): Promise<VerificationResult> {
    const wasm = this.getWasm();
    try {
      const result = wasm.verify(
        prepareProof,
        prepareVk,
        prepareInstance,
        showProof,
        showVk,
        showInstance,
      );
      return {
        valid: result.valid,
        preparePublicValues: result.prepare_public_values,
        showPublicValues: result.show_public_values,
        error: result.error ?? undefined,
      };
    } catch (error) {
      // Handle deserialization and verification errors from WASM
      const errorMessage = error instanceof Error ? error.message : String(error);
      return {
        valid: false,
        preparePublicValues: [],
        showPublicValues: [],
        error: errorMessage,
      };
    }
  }
}
