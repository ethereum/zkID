// Orchestrates the full Prepare -> Show proving pipeline.

import { WasmBridge } from "./wasm-bridge.js";
import { WitnessCalculator } from "./witness-calculator.js";
import { Credential } from "./credential.js";
import { buildJwtCircuitInputs } from "./inputs/jwt-input-builder.js";
import {
  buildShowCircuitInputs,
  signDeviceNonce,
} from "./inputs/show-input-builder.js";
import { circuitInputsToJson, base64Encode } from "./utils.js";
import { buildRevocationWitness, fromLimbs } from "./revocation.js";
import { InputError, ProofError } from "./errors.js";
import { base64Decode } from "./utils.js";
import {
  DEFAULT_SHOW_PARAMS,
} from "./types.js";
import {
  CLAIM_VALUES_WITNESS_START,
  CLAIM_IDENTITY_WITNESS_START,
  JWT_PARAMS_BY_SIZE,
  selectVcSizeForSigningInput,
  type VcSize,
} from "./sizing.js";
import {
  assertNormalizationSupports,
  compilePredicateExpression,
  type CompiledPredicates,
} from "./predicates.js";
import type {
  ProofPublicValues,
  SerializedProofJSON,
  JwtCircuitParams,
  PrecomputeRequest,
  PrecomputedCredential,
  PrecomputeTiming,
  PresentRequest,
  PresentationProof,
  PresentationTiming,
  SerializedPrecomputedCredentialJSON,
  EcdsaPublicKey,
  ClaimNormalization,
} from "./types.js";

const SDK_VERSION = "0.1.0";

export class Prover {
  private bridge: WasmBridge;
  private witnessCalculator: WitnessCalculator | null = null;

  constructor(bridge: WasmBridge, witnessCalculator?: WitnessCalculator) {
    this.bridge = bridge;
    this.witnessCalculator = witnessCalculator ?? null;
  }

  async precompute(request: PrecomputeRequest): Promise<PrecomputedCredential> {
    const startTime = performance.now();
    const timing: Partial<PrecomputeTiming> = {};

    let t1 = performance.now();
    const credential = Credential.parse(
      request.jwt,
      request.disclosures,
      request.profile,
    );
    timing.parseCredentialMs = performance.now() - t1;

    const deviceKey = credential.deviceBindingKey;
    if (!deviceKey) {
      throw new InputError(
        "INVALID_JWT",
        "JWT payload does not contain device binding key (cnf.jwk)",
      );
    }

    const compiled: CompiledPredicates = compilePredicateExpression(
      request.predicates,
      credential.claims,
    );

    const birthdayClaimIndex =
      compiled.birthdayClaimIndex ?? credential.findBirthdayClaim() ?? 0;
    const birthdayClaim = credential.claims[birthdayClaimIndex];
    if (!birthdayClaim) {
      throw new InputError(
        "CLAIM_NOT_FOUND",
        `No claim at index ${birthdayClaimIndex}`,
      );
    }

    t1 = performance.now();
    const signingInputByteLength =
      credential.b64Header.length + 1 + credential.b64Payload.length;
    const vcSize: VcSize = selectVcSizeForSigningInput(signingInputByteLength);
    const jwtParams: JwtCircuitParams = JWT_PARAMS_BY_SIZE[vcSize];
    const decodeFlags = compiled.decodeFlags;
    const claimFormats = compiled.claimFormats;
    const additionalMatches = credential.disclosureHashes;

    const jwtInputs = buildJwtCircuitInputs(
      credential,
      request.issuerPublicKey,
      jwtParams,
      additionalMatches,
      decodeFlags,
      claimFormats,
    );
    const jwtInputsJson = circuitInputsToJson(jwtInputs);
    timing.buildInputsMs = performance.now() - t1;

    t1 = performance.now();
    const prepareWitnessBytes = await this.generatePrepareWitness(
      jwtInputsJson,
      vcSize,
    );
    timing.prepareWitnessMs = performance.now() - t1;

    // Extract normalized claim values from the JWT witness so present() doesn't
    // have to recompute them. They are private signals (see
    // CLAIM_VALUES_WITNESS_START) — the public IO holds only KeyBindingX/Y.
    // Done in parallel with the SNARK prove below.
    const maxClaims = jwtParams.maxMatches - 2;
    const claimStart = CLAIM_VALUES_WITNESS_START[vcSize];
    const identityStart = CLAIM_IDENTITY_WITNESS_START[vcSize];
    // Read normalized values AND per-slot attribute identities H(name) from the
    // same JWT witness. Identities are carried to Show via comm_W_shared to bind
    // predicate slots to attribute names (Items 1+3); the SDK never hashes.
    const witnessSlicesPromise = this.witnessCalculator
      ? this.calculateJwtWitness(jwtInputsJson, vcSize).then((w) => ({
          normalizedClaimValues: w.slice(claimStart, claimStart + maxClaims),
          claimIdentifierHashes: w.slice(identityStart, identityStart + maxClaims),
        }))
      : Promise.resolve({ normalizedClaimValues: [] as bigint[], claimIdentifierHashes: [] as bigint[] });

    t1 = performance.now();
    const prepareResult = await this.bridge.precomputeFromWitness(
      request.keys.prepareProvingKey,
      prepareWitnessBytes,
      vcSize,
    );
    timing.prepareProveMs = performance.now() - t1;

    const { normalizedClaimValues, claimIdentifierHashes } = await witnessSlicesPromise;
    timing.totalMs = performance.now() - startTime;

    return this.buildPrecomputedCredential(
      prepareResult.proof,
      prepareResult.instance,
      prepareResult.witness,
      credential,
      birthdayClaimIndex,
      birthdayClaim.raw,
      deviceKey,
      normalizedClaimValues,
      claimIdentifierHashes,
      // Taken from the built inputs rather than from `compiled`: the builder
      // pads or truncates both arrays to the circuit's claim slot count, so
      // these are what the circuit actually ran on and what its public IO
      // reports.
      {
        decodeFlags: jwtInputs.decodeFlags,
        claimFormats: jwtInputs.claimFormats.map((v) => Number(v)),
      },
      timing as PrecomputeTiming,
    );
  }

  async present(request: PresentRequest): Promise<PresentationProof> {
    const startTime = performance.now();
    const timing: Partial<PresentationTiming> = {};

    const { precomputed, verifierNonce, devicePrivateKey, keys } = request;
    const deviceSignature = signDeviceNonce(verifierNonce, devicePrivateKey);

    const parsed = Credential.parse(
      precomputed.credential.jwt,
      precomputed.credential.disclosures,
      request.profile,
    );
    const compiled = compilePredicateExpression(request.predicates, parsed.claims);

    // The normalized values below were produced by an earlier precompute() run.
    // They are only valid inputs to these predicates if that run decoded the
    // same claims under the same formats.
    assertNormalizationSupports(precomputed.claimNormalization, compiled);

    if (!request.revocation?.secret || !request.revocation.registry) {
      throw new InputError("MISSING_REVOCATION_INPUTS", "present() requires revocation: { secret, registry }");
    }
    const revocationCommitment = parsed.revocationCommitment;
    if (revocationCommitment === null) {
      throw new InputError("CLAIM_NOT_FOUND", "Credential has no revocation_commitment claim");
    }
    const revocation = buildRevocationWitness(
      request.revocation.secret,
      revocationCommitment,
      request.revocation.registry,
      DEFAULT_SHOW_PARAMS.revocationMaxDepth,
    );

    const showInputs = buildShowCircuitInputs(
      DEFAULT_SHOW_PARAMS,
      verifierNonce,
      deviceSignature,
      precomputed.deviceKey,
      {
        normalizedClaimValues: precomputed.normalizedClaimValues,
        claimIdentifierHashes: precomputed.claimIdentifierHashes,
        predicates: compiled.predicates,
        logicExpression: compiled.logicExpression,
        revocation,
      },
    );
    const showInputsJson = circuitInputsToJson(showInputs);

    let t1 = performance.now();
    const showWitnessBytes = await this.generateShowWitness(showInputsJson);
    timing.showWitnessMs = performance.now() - t1;

    t1 = performance.now();
    const showResult = await this.bridge.precomputeShowFromWitness(
      keys.showProvingKey,
      showWitnessBytes,
    );
    timing.showProveMs = performance.now() - t1;

    t1 = performance.now();
    const presentResult = await this.bridge.present(
      keys.prepareProvingKey,
      precomputed.prepareInstance,
      precomputed.prepareWitness,
      keys.showProvingKey,
      showResult.instance,
      showResult.witness,
    );
    timing.presentMs = performance.now() - t1;
    timing.totalMs = performance.now() - startTime;

    let expressionResult = false;
    let revocationRoot = 0n;
    if (this.witnessCalculator) {
      const inputs = this.parseJsonToBigInt(showInputsJson);
      const showWitness = await this.witnessCalculator.calculateShowWitness(inputs);
      expressionResult = showWitness[1] === 1n;
      revocationRoot = fromLimbs(showWitness[2]!, showWitness[3]!);
    }

    const publicValues: ProofPublicValues = { expressionResult, revocationRoot };

    return this.buildPresentationProof(
      presentResult.prepareProof,
      presentResult.prepareInstance,
      presentResult.showProof,
      presentResult.showInstance,
      publicValues,
      timing as PresentationTiming,
    );
  }

  private async generatePrepareWitness(
    inputsJson: string,
    vcSize?: import("./wasm-bridge.js").VcSize,
  ): Promise<Uint8Array> {
    if (!this.witnessCalculator) {
      throw new ProofError(
        "WITNESS_GENERATION_FAILED",
        "WitnessCalculator not initialized. Provide one in the Prover constructor or via OpenAC.init({ assetsDir }).",
      );
    }
    const inputs = this.parseJsonToBigInt(inputsJson);
    return await this.witnessCalculator.calculateJwtWitnessWtns(inputs, vcSize);
  }

  private async generateShowWitness(inputsJson: string): Promise<Uint8Array> {
    if (!this.witnessCalculator) {
      throw new ProofError(
        "WITNESS_GENERATION_FAILED",
        "WitnessCalculator not initialized. Provide one in the Prover constructor or via OpenAC.init({ assetsDir }).",
      );
    }
    const inputs = this.parseJsonToBigInt(inputsJson);
    return await this.witnessCalculator.calculateShowWitnessWtns(inputs);
  }

  private async calculateJwtWitness(inputsJson: string, vcSize?: VcSize): Promise<bigint[]> {
    if (!this.witnessCalculator) {
      throw new ProofError(
        "WITNESS_GENERATION_FAILED",
        "WitnessCalculator not initialized.",
      );
    }
    const inputs = this.parseJsonToBigInt(inputsJson);
    return await this.witnessCalculator.calculateJwtWitness(inputs, vcSize);
  }

  private async calculateShowWitness(inputsJson: string): Promise<bigint[]> {
    if (!this.witnessCalculator) {
      throw new ProofError(
        "WITNESS_GENERATION_FAILED",
        "WitnessCalculator not initialized.",
      );
    }
    const inputs = this.parseJsonToBigInt(inputsJson);
    return await this.witnessCalculator.calculateShowWitness(inputs);
  }

  private parseJsonToBigInt(json: string): Record<string, unknown> {
    return JSON.parse(json, (_key, value) => {
      if (typeof value === "string" && /^-?\d+$/.test(value)) {
        return BigInt(value);
      }
      return value;
    });
  }

  private buildPrecomputedCredential(
    prepareProof: Uint8Array,
    prepareInstance: Uint8Array,
    prepareWitness: Uint8Array,
    credential: Credential,
    birthdayClaimIndex: number,
    birthdayClaim: string,
    deviceKey: EcdsaPublicKey,
    normalizedClaimValues: bigint[],
    claimIdentifierHashes: bigint[],
    claimNormalization: ClaimNormalization,
    timing: PrecomputeTiming,
  ): PrecomputedCredential {
    const result: PrecomputedCredential = {
      prepareProof,
      prepareInstance,
      prepareWitness,
      credential: {
        jwt: credential.token,
        disclosures: credential.claims.map((c) => c.raw),
        deviceBindingKey: deviceKey,
      },
      birthdayClaimIndex,
      birthdayClaim,
      deviceKey,
      normalizedClaimValues,
      claimIdentifierHashes,
      claimNormalization,
      timing,

      serialize(): Uint8Array {
        return serializePrecomputed(result);
      },

      toJSON(): SerializedPrecomputedCredentialJSON {
        return {
          version: SDK_VERSION,
          prepareProof: base64Encode(result.prepareProof),
          prepareInstance: base64Encode(result.prepareInstance),
          prepareWitness: base64Encode(result.prepareWitness),
          credential: result.credential,
          birthdayClaimIndex: result.birthdayClaimIndex,
          birthdayClaim: result.birthdayClaim,
          deviceKey: result.deviceKey,
          normalizedClaimValues: result.normalizedClaimValues.map((v) => v.toString()),
          claimIdentifierHashes: result.claimIdentifierHashes.map((v) => v.toString()),
          claimNormalization: {
            decodeFlags: [...result.claimNormalization.decodeFlags],
            claimFormats: [...result.claimNormalization.claimFormats],
          },
        };
      },
    };
    return result;
  }

  private buildPresentationProof(
    prepareProof: Uint8Array,
    prepareInstance: Uint8Array,
    showProof: Uint8Array,
    showInstance: Uint8Array,
    publicValues: ProofPublicValues,
    timing: PresentationTiming,
  ): PresentationProof {
    const result: PresentationProof = {
      prepareProof,
      prepareInstance,
      showProof,
      showInstance,
      publicValues,
      timing,

      serialize(): Uint8Array {
        return serializeProofBundle({
          prepareProof: result.prepareProof,
          showProof: result.showProof,
          prepareInstance: result.prepareInstance,
          showInstance: result.showInstance,
        });
      },

      toBase64(): string {
        return base64Encode(result.serialize());
      },

      toJSON(): SerializedProofJSON {
        return {
          version: SDK_VERSION,
          prepareProof: base64Encode(result.prepareProof),
          showProof: base64Encode(result.showProof),
          prepareInstance: base64Encode(result.prepareInstance),
          showInstance: base64Encode(result.showInstance),
          publicValues: {
            expressionResult: result.publicValues.expressionResult,
            revocationRoot: result.publicValues.revocationRoot.toString(),
          },
        };
      },
    };
    return result;
  }
}

// Serialize a proof bundle into a single binary blob.
// Format: [4 bytes: length][bytes] for each of: version, prepareProof, showProof, prepareInstance, showInstance
interface ProofBundle {
  prepareProof: Uint8Array;
  showProof: Uint8Array;
  prepareInstance: Uint8Array;
  showInstance: Uint8Array;
}

function serializeProofBundle(result: ProofBundle): Uint8Array {
  const version = new TextEncoder().encode(SDK_VERSION);
  const parts = [
    version,
    result.prepareProof,
    result.showProof,
    result.prepareInstance,
    result.showInstance,
  ];

  let totalSize = 0;
  for (const part of parts) {
    totalSize += 4 + part.length;
  }

  const buffer = new Uint8Array(totalSize);
  const view = new DataView(buffer.buffer);
  let offset = 0;

  for (const part of parts) {
    view.setUint32(offset, part.length, true);
    offset += 4;
    buffer.set(part, offset);
    offset += part.length;
  }

  return buffer;
}

export function deserializeProofBundle(data: Uint8Array): {
  version: string;
  prepareProof: Uint8Array;
  showProof: Uint8Array;
  prepareInstance: Uint8Array;
  showInstance: Uint8Array;
} {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let offset = 0;

  function readPart(): Uint8Array {
    const len = view.getUint32(offset, true);
    offset += 4;
    const part = data.slice(offset, offset + len);
    offset += len;
    return part;
  }

  const versionBytes = readPart();
  const version = new TextDecoder().decode(versionBytes);
  const prepareProof = readPart();
  const showProof = readPart();
  const prepareInstance = readPart();
  const showInstance = readPart();

  return { version, prepareProof, showProof, prepareInstance, showInstance };
}

function serializePrecomputed(precomputed: PrecomputedCredential): Uint8Array {
  const json = JSON.stringify(precomputed.toJSON());
  return new TextEncoder().encode(json);
}

export function deserializePrecomputed(data: Uint8Array): PrecomputedCredential {
  const json: SerializedPrecomputedCredentialJSON = JSON.parse(
    new TextDecoder().decode(data),
  );

  // Blobs written before claimNormalization existed carry normalized values
  // with no record of the formats that produced them, so present() cannot tell
  // whether they answer its predicates. Reject rather than guess.
  const claimNormalization = json.claimNormalization;
  if (
    !claimNormalization ||
    !Array.isArray(claimNormalization.decodeFlags) ||
    !Array.isArray(claimNormalization.claimFormats)
  ) {
    throw new InputError(
      "CLAIM_FORMAT_MISMATCH",
      "Precomputed credential has no claim normalization metadata. " +
        "It was serialized by an older SDK version; run precompute() again.",
    );
  }

  const result: PrecomputedCredential = {
    prepareProof: base64Decode(json.prepareProof),
    prepareInstance: base64Decode(json.prepareInstance),
    prepareWitness: base64Decode(json.prepareWitness),
    credential: json.credential,
    birthdayClaimIndex: json.birthdayClaimIndex,
    birthdayClaim: json.birthdayClaim,
    deviceKey: json.deviceKey,
    normalizedClaimValues: (json.normalizedClaimValues ?? []).map((s) => BigInt(s)),
    claimIdentifierHashes: (json.claimIdentifierHashes ?? []).map((s) => BigInt(s)),
    claimNormalization: {
      decodeFlags: [...claimNormalization.decodeFlags],
      claimFormats: [...claimNormalization.claimFormats],
    },
    timing: {
      parseCredentialMs: 0,
      buildInputsMs: 0,
      prepareWitnessMs: 0,
      prepareProveMs: 0,
      totalMs: 0,
    },

    serialize(): Uint8Array {
      return serializePrecomputed(result);
    },

    toJSON(): SerializedPrecomputedCredentialJSON {
      return json;
    },
  };

  return result;
}
