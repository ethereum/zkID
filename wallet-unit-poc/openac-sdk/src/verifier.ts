import { WasmBridge } from "./wasm-bridge.js";
import { deserializeProofBundle } from "./prover.js";
import {
  buildShowStatementPublicValues,
  showNumOutputs,
} from "./inputs/show-statement.js";
import { extractClaimNormalizationFromPreparePublicValues } from "./inputs/prepare-public-io.js";
import { checkNormalizationSupports } from "./predicates.js";
import { fromLimbs } from "./limbs.js";
import { DEFAULT_SHOW_PARAMS } from "./types.js";
import type {
  VerificationResult,
  VerifyingKeys,
  SerializedProof,
  ExpectedStatement,
} from "./types.js";

/**
 * Parse a Show public value (a serialized secq256r1 scalar) into a bigint.
 *
 * The WASM `verify` formats each scalar with Rust's `{:?}`, which renders ff
 * field elements as a big-endian `0x`-prefixed hex string. We extract that hex
 * run and parse it; a bare decimal string is accepted as a fallback.
 */
function parseScalar(value: string): bigint {
  if (!value) return 0n;
  const hex = value.match(/0x([0-9a-fA-F]+)/);
  if (hex) return BigInt("0x" + hex[1]);
  const dec = value.match(/-?\d+/);
  if (dec) return BigInt(dec[0]);
  return 0n;
}

export class Verifier {
  private bridge: WasmBridge;

  private static failure(
    error: string,
    startTime: number,
  ): VerificationResult {
    return {
      valid: false,
      expressionResult: null,
      deviceKey: null,
      issuerRoot: null,
      revocationRoot: null,
      verifyMs: performance.now() - startTime,
      error,
    };
  }

  constructor(bridge: WasmBridge) {
    this.bridge = bridge;
  }

  async verifyProof(
    proof: SerializedProof,
    keys: VerifyingKeys,
    expected: ExpectedStatement,
  ): Promise<VerificationResult> {
    const startTime = performance.now();

    let bundle;
    try {
      bundle = deserializeProofBundle(proof);
    } catch {
      return Verifier.failure("Invalid proof format", startTime);
    }

    return this.verifyInternal(
      () =>
        this.bridge.verify(
          bundle.prepareProof,
          keys.prepareVerifyingKey,
          bundle.prepareInstance,
          bundle.showProof,
          keys.showVerifyingKey,
          bundle.showInstance,
        ),
      expected,
      startTime,
    );
  }

  async verifyComponents(
    prepareProof: Uint8Array,
    showProof: Uint8Array,
    keys: VerifyingKeys,
    prepareInstance: Uint8Array,
    showInstance: Uint8Array,
    expected: ExpectedStatement,
  ): Promise<VerificationResult> {
    const startTime = performance.now();

    return this.verifyInternal(
      () =>
        this.bridge.verify(
          prepareProof,
          keys.prepareVerifyingKey,
          prepareInstance,
          showProof,
          keys.showVerifyingKey,
          showInstance,
        ),
      expected,
      startTime,
    );
  }

  /**
   * Run the SNARK verification, then bind the result to the verifier's expected
   * statement: recompute the Show proof's public values (nonce hash + compiled
   * predicate program) and require them to match the proof's public IO
   * index-by-index. Any mismatch fails verification, so a `valid` result also
   * means the proof was produced for this exact nonce and predicate program.
   *
   * The predicate program says which claim slots the policy reads, and the
   * Prepare proof's public IO says how each of those slots was decoded and
   * normalized. Both are required to match the expected statement, since the
   * same predicate over the same slot means different things under different
   * normalization.
   *
   * The issuer is hidden: Show outputs the issuer registry root and the
   * revocation root, which `expected.isValidIssuerRoot` and
   * `expected.isValidRevocationRoot` must accept. A check that throws fails the
   * verification rather than propagating.
   */
  private async verifyInternal(
    runVerify: () => Promise<{
      valid: boolean;
      preparePublicValues: string[];
      showPublicValues: string[];
      error?: string;
    }>,
    expected: ExpectedStatement,
    startTime: number,
  ): Promise<VerificationResult> {
    // Build the public-value vector the verifier expects from its own nonce and
    // predicate program (in circuit terms). No credential claims are consulted:
    // the verifier decides what statement it required, independent of anything
    // the holder discloses. A malformed expectation surfaces as an explicit
    // error rather than a silent mismatch.
    let expectedStatementValues: bigint[];
    try {
      expectedStatementValues = buildShowStatementPublicValues(
        DEFAULT_SHOW_PARAMS,
        expected.nonce,
        expected.predicates,
        expected.logicExpression,
      );
    } catch (e) {
      return Verifier.failure(
        `Invalid expected statement: ${e instanceof Error ? e.message : String(e)}`,
        startTime,
      );
    }

    const result = await runVerify();

    if (!result.valid) {
      return Verifier.failure(
        result.error ?? "Proof verification failed",
        startTime,
      );
    }

    // The Prepare proof's public IO carries the decodeFlags/claimFormats the
    // claim values were normalized under.
    const preparePublicValues = result.preparePublicValues.map(parseScalar);
    let claimNormalization;
    try {
      // Cross-check the Prepare public-IO length against the claim-slot count
      // the verifier expects (Item 10): the vector length is prover-controlled,
      // so a forked prover could truncate it to a different valid shape.
      const expectedClaimCount = DEFAULT_SHOW_PARAMS.nClaims;
      claimNormalization = extractClaimNormalizationFromPreparePublicValues(
        preparePublicValues,
        expectedClaimCount,
      );
    } catch (e) {
      return Verifier.failure(
        e instanceof Error ? e.message : String(e),
        startTime,
      );
    }

    // The normalization is checked here rather than reported, because the
    // policy binding below compares predicates against claim values whose
    // meaning depends on it.
    const normalizationError = checkNormalizationSupports(
      claimNormalization,
      expected.claimNormalization,
    );
    if (normalizationError) {
      return Verifier.failure(
        `Claim normalization mismatch: ${normalizationError}`,
        startTime,
      );
    }

    // Item 11: the normalization that actually ran must cover the slots the
    // policy reads. A predicate over an undecoded slot compares against 0 (a
    // vacuous pass), so require every referenced slot to be normalized.
    for (const spec of expected.predicates) {
      if (claimNormalization.decodeFlags[spec.claimRef] !== 1) {
        return Verifier.failure(
          `Policy references claim slot ${spec.claimRef} which was not normalized`,
          startTime,
        );
      }
      if (
        spec.rhs.kind === "claimRef" &&
        claimNormalization.decodeFlags[spec.rhs.index] !== 1
      ) {
        return Verifier.failure(
          `Policy RHS references claim slot ${spec.rhs.index} which was not normalized`,
          startTime,
        );
      }
    }

    // Public IO layout: [0] expressionResult, [1..3] issuerRoot [hi, lo],
    // [3..5] revocationRoot [hi, lo], then the bound verifier statement
    // (messageHash + predicate program).
    const publicValues = result.showPublicValues.map(parseScalar);
    const expressionResult = (publicValues[0] ?? 0n) !== 0n;

    const boundValues = publicValues.slice(showNumOutputs(DEFAULT_SHOW_PARAMS));
    if (boundValues.length !== expectedStatementValues.length) {
      return Verifier.failure(
        `Statement binding size mismatch: proof exposes ${boundValues.length} bound values, expected ${expectedStatementValues.length}`,
        startTime,
      );
    }

    for (let i = 0; i < expectedStatementValues.length; i++) {
      if (boundValues[i] !== expectedStatementValues[i]) {
        // Index 0 of the bound values is messageHash (freshness); the rest are
        // the predicate program (policy).
        const kind = i === 0 ? "nonce" : "policy";
        return Verifier.failure(
          `Statement binding mismatch (${kind}): proof was not generated for the expected nonce and policy`,
          startTime,
        );
      }
    }

    let issuerRoot: bigint;
    let revocationRoot: bigint;
    try {
      issuerRoot = fromLimbs(publicValues[1] ?? 0n, publicValues[2] ?? 0n);
      revocationRoot = fromLimbs(publicValues[3] ?? 0n, publicValues[4] ?? 0n);
    } catch (e) {
      return Verifier.failure(e instanceof Error ? e.message : String(e), startTime);
    }
    let issuerRootAccepted: boolean;
    try {
      issuerRootAccepted = await expected.isValidIssuerRoot(issuerRoot);
    } catch (e) {
      return Verifier.failure(
        `Issuer root check failed: ${e instanceof Error ? e.message : String(e)}`,
        startTime,
      );
    }
    if (issuerRootAccepted !== true) {
      return Verifier.failure("Issuer root is not accepted", startTime);
    }

    let rootAccepted: boolean;
    try {
      rootAccepted = await expected.isValidRevocationRoot(revocationRoot);
    } catch (e) {
      return Verifier.failure(
        `Revocation root check failed: ${e instanceof Error ? e.message : String(e)}`,
        startTime,
      );
    }
    if (rootAccepted !== true) {
      return Verifier.failure(
        "Revocation root is not accepted: the registry state is stale or unknown",
        startTime,
      );
    }

    return {
      valid: true,
      expressionResult,
      deviceKey: null,
      issuerRoot,
      revocationRoot,
      verifyMs: performance.now() - startTime,
    };
  }
}
