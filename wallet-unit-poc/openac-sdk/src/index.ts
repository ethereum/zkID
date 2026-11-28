import { WasmBridge } from "./wasm-bridge.js";
import type { VcSize } from "./sizing.js";
import { WitnessCalculator } from "./witness-calculator.js";
import { Prover } from "./prover.js";
import { Verifier } from "./verifier.js";
import { readFile } from "fs/promises";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { WasmError } from "./errors.js";
import type {
  OpenACConfig,
  VerificationResult,
  VerifyingKeys,
  KeySet,
  SerializedKeySet,
  SerializedProof,
  PrecomputeRequest,
  PrecomputedCredential,
  PresentRequest,
  PresentationProof,
  ExpectedStatement,
} from "./types.js";

export const DEFAULT_KEYS_BASE_URL =
  "https://pub-d941fd6fc0c84bd892810e681a55edcd.r2.dev/openac-5.0.0";

export class OpenAC {
  private bridge: WasmBridge;
  private prover: Prover;
  private verifier: Verifier;
  private config: OpenACConfig;

  private constructor(
    bridge: WasmBridge,
    prover: Prover,
    verifier: Verifier,
    config: OpenACConfig,
  ) {
    this.bridge = bridge;
    this.prover = prover;
    this.verifier = verifier;
    this.config = config;
  }

  static async init(config: OpenACConfig = {}): Promise<OpenAC> {
    const bridge = new WasmBridge();

    if (config.wasmModule) {
      if (typeof config.wasmModule.default === "function") {
        await config.wasmModule.default();
      }
      bridge.initWithModule(config.wasmModule);
    } else {
      await bridge.init(config.wasmPath);
    }

    let witnessCalculator: WitnessCalculator | undefined;
    try {
      witnessCalculator = new WitnessCalculator(config.assetsDir);
      await witnessCalculator.init();
    } catch (e) {
      witnessCalculator = undefined;
      if (process.env.OPENAC_DEBUG) {
        console.warn(
          `[openac-sdk] WitnessCalculator unavailable: ${e instanceof Error ? e.message : String(e)}`,
        );
      }
    }

    const prover = new Prover(bridge, witnessCalculator);
    const verifier = new Verifier(bridge);

    return new OpenAC(bridge, prover, verifier, config);
  }

  async loadKeysFromUrl(vcSize: VcSize, baseUrl?: string): Promise<KeySet> {
    const url = baseUrl ?? this.config.keysBaseUrl ?? DEFAULT_KEYS_BASE_URL;
    const keys = await this.bridge.loadKeys(url, vcSize);
    return createKeySet(
      keys.preparePk,
      keys.prepareVk,
      keys.showPk,
      keys.showVk,
    );
  }

  async loadKeys(data: SerializedKeySet): Promise<KeySet> {
    return createKeySet(
      data.prepareProvingKey,
      data.prepareVerifyingKey,
      data.showProvingKey,
      data.showVerifyingKey,
    );
  }

  async loadBundledShowVerifyingKey(vcSize: VcSize): Promise<Uint8Array> {
    const here = dirname(fileURLToPath(import.meta.url));
    const candidates = [
      join(here, "..", "assets", "keys", `${vcSize}_show_verifying.key`),
      join(here, "assets", "keys", `${vcSize}_show_verifying.key`),
    ];
    for (const path of candidates) {
      try {
        const buf = await readFile(path);
        return new Uint8Array(buf);
      } catch {
        continue;
      }
    }
    throw new WasmError(
      "KEY_LOAD_FAILED",
      `Bundled show VK for size '${vcSize}' not found. Expected at assets/keys/${vcSize}_show_verifying.key`,
    );
  }

  async precompute(request: PrecomputeRequest): Promise<PrecomputedCredential> {
    return this.prover.precompute(request);
  }

  async present(request: PresentRequest): Promise<PresentationProof> {
    return this.prover.present(request);
  }

  async verify(
    proof: PresentationProof,
    keys: VerifyingKeys,
    expected: ExpectedStatement,
  ): Promise<VerificationResult> {
    return this.verifier.verifyComponents(
      proof.prepareProof,
      proof.showProof,
      keys,
      proof.prepareInstance,
      proof.showInstance,
      expected,
    );
  }

  async verifyProof(
    proof: SerializedProof,
    keys: VerifyingKeys,
    expected: ExpectedStatement,
  ): Promise<VerificationResult> {
    return this.verifier.verifyProof(proof, keys, expected);
  }

  async verifyComponents(
    prepareProof: Uint8Array,
    showProof: Uint8Array,
    keys: VerifyingKeys,
    prepareInstance: Uint8Array,
    showInstance: Uint8Array,
    expected: ExpectedStatement,
  ): Promise<VerificationResult> {
    return this.verifier.verifyComponents(
      prepareProof,
      showProof,
      keys,
      prepareInstance,
      showInstance,
      expected,
    );
  }

  get isReady(): boolean {
    return this.bridge.isInitialized;
  }
}

function createKeySet(
  prepareProvingKey: Uint8Array,
  prepareVerifyingKey: Uint8Array,
  showProvingKey: Uint8Array,
  showVerifyingKey: Uint8Array,
): KeySet {
  return {
    prepareProvingKey,
    prepareVerifyingKey,
    showProvingKey,
    showVerifyingKey,

    verifyingKeys(): VerifyingKeys {
      return { prepareVerifyingKey, showVerifyingKey };
    },

    serialize(): SerializedKeySet {
      return {
        prepareProvingKey,
        prepareVerifyingKey,
        showProvingKey,
        showVerifyingKey,
      };
    },
  };
}

// Re-exports
export { Credential } from "./credential.js";
export type { CredentialProfileOptions } from "./credential.js";
export { Prover, deserializePrecomputed } from "./prover.js";
export { Verifier } from "./verifier.js";
export { WitnessCalculator } from "./witness-calculator.js";
export { NativeBackend } from "./native-backend.js";
export type { NativeBackendConfig } from "./native-backend.js";
// Typed predicate DSL (recommended public API).
export {
  compilePredicateExpression,
  assertNormalizationSupports,
  checkNormalizationSupports,
  requiredNormalization,
} from "./predicates.js";
// Verifier-statement binding helpers (nonce hash + compiled predicate program).
export {
  computeMessageHash,
  buildShowStatementFields,
  buildShowStatementPublicValues,
} from "./inputs/show-statement.js";
// Issuer-key helpers: convert a key to the coordinates the circuits use, and
// read those coordinates back out of a proof's public values.
export { issuerPublicKeyToPoint } from "./inputs/issuer-key.js";
// Readers for the Prepare proof's public IO: the issuer key, and the claim
// normalization the proof's claim values were produced under.
export {
  extractIssuerKeyFromPreparePublicValues,
  extractClaimNormalizationFromPreparePublicValues,
} from "./inputs/prepare-public-io.js";
export type { IssuerKeyPoint } from "./inputs/prepare-public-io.js";
// Revocation: issuer-signed values, their registry commitments, the SHA-256
// LeanIMT+ registry and root checks.
export {
  REVOCATION_MAX_DEPTH,
  REVOCATION_VALUE_CLAIM,
  REVOCATION_COMMITMENT_TAG,
  generateRevocationValue,
  computeRevocationCommitment,
  encodeRevocationValue,
  decodeRevocationValue,
  createRevocationRegistry,
  revocationRegistryFromLeaves,
  acceptRevocationRoots,
  buildRevocationWitness,
} from "./revocation.js";
export type {
  RevocationRegistryLike,
  RevocationRequest,
  RevocationRootCheck,
  RevocationWitness,
} from "./revocation.js";
export { RevocationRegistry, sha256Scheme } from "@coordination-network/revocation-registry";
// Circuit-level predicate program types/constants, for building ExpectedStatement.
export { PredicateOp, LogicToken } from "./inputs/show-input-builder.js";
export type { PredicateSpec, PredicateRhs } from "./inputs/show-input-builder.js";
export type {
  Predicate,
  PredicateExpression,
  Comparator,
  ClaimFormatHint,
  CompiledPredicates,
} from "./predicates.js";

export {
  OpenACError,
  SetupError,
  ProofError,
  VerificationError,
  InputError,
  WasmError,
} from "./errors.js";

export type {
  OpenACConfig,
  ProofPublicValues,
  VerificationResult,
  ExpectedStatement,
  ProvenIssuerKey,
  VerifyingKeys,
  KeySet,
  SerializedKeySet,
  SerializedProof,
  SerializedProofJSON,
  DisclosedClaim,
  EcdsaPublicKey,
  EcdsaPrivateKey,
  IssuerPublicKey,
  PemPublicKey,
  ErrorCode,
  PrecomputeRequest,
  PrecomputedCredential,
  ClaimNormalization,
  PrecomputeTiming,
  PresentRequest,
  PresentationProof,
  PresentationTiming,
  SerializedCredential,
  SerializedPrecomputedCredentialJSON,
} from "./types.js";

export {
  base64urlToBase64,
  base64ToBase64url,
  base64Decode,
  base64Encode,
  base64urlEncode,
  base64ToBigInt,
  base64urlToBigInt,
  bigintToBase64url,
  bytesToBigInt,
  bigintToBytes,
  uint8ArrayToBigIntArray,
  stringToPaddedBigIntArray,
  sha256Pad,
  sha256Hash,
  sha256HashString,
  encodeClaims,
  modInverse,
  modScalarField,
  circuitInputsToJson,
  jwkPointToBigInt,
  P256_SCALAR_ORDER,
} from "./utils.js";

export { DEFAULT_JWT_PARAMS, DEFAULT_SHOW_PARAMS } from "./types.js";
