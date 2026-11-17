import type { WitnessTester } from "circomkit";
import { circomkit } from "../common/index.ts";
import { generateMockData } from "../../src/mock-vc-generator.ts";
import { LogicToken, generateShowCircuitParams, generateShowInputs, predicateToken, signDeviceNonce } from "../../src/show.ts";
import { base64ToBigInt, base64urlToBase64 } from "../../src/utils.ts";
import { bindPredicateName, bindPredicateRhsName } from "../common/claim-identity.ts";
import assert from "assert";
import { p256 } from "@noble/curves/nist.js";

describe("Show Circuit - Device Binding Verification", () => {
  let circuit: WitnessTester<
    [
      "deviceKeyX",
      "deviceKeyY",
      "sig_r",
      "sig_s_inverse",
      "messageHash",
      "predicateLen",
      "claimValues",
      "predicateClaimRefs",
      "predicateOps",
      "predicateRhsIsRef",
      "predicateRhsValues",
      "tokenTypes",
      "tokenValues",
      "exprLen"
    ],
    ["expressionResult"]
  >;
  const claim = "WyJGc2w4ZWpObEFNT2Vqc1lTdjc2Z1NnIiwicm9jX2JpcnRoZGF5IiwiMTA0MDYwNSJd";

  before(async () => {
    const RECOMPILE = true;
    circuit = await circomkit.WitnessTester(`Show`, {
      file: "show",
      template: "Show",
      params: [4, 2, 8, 64, 8, 0],
      recompile: RECOMPILE,
    });
    console.log("#constraints:", await circuit.getConstraintCount());
  });

  describe("Device Binding Key Verification", () => {
    it("should verify device signature on nonce matches device binding key", async () => {
      const mockData = await generateMockData({
        circuitParams: [2048, 2000, 6, 50, 128],
      });

      const verifierNonce = "challenge-nonce-12345";
      const deviceSignature = signDeviceNonce(verifierNonce, mockData.devicePrivateKey);

      const params = generateShowCircuitParams(mockData.circuitParams);
      const inputs = generateShowInputs(params, verifierNonce, deviceSignature, mockData.deviceKey, [], [], [0n]);
      await bindPredicateName(inputs, 0, 0, "name");

      const witness = await circuit.calculateWitness(inputs);
      await circuit.expectConstraintPass(witness);
    });

    it("should fail when device signature doesn't match device binding key", async () => {
      const mockData = await generateMockData({
        circuitParams: [2048, 2000, 6, 50, 128],
      });

      const wrongPrivateKey = p256.utils.randomSecretKey();
      const verifierNonce = "challenge-nonce-12345";
      const deviceSignature = signDeviceNonce(verifierNonce, wrongPrivateKey);

      const params = generateShowCircuitParams(mockData.circuitParams);

      assert.throws(() => {
        generateShowInputs(params, verifierNonce, deviceSignature, mockData.deviceKey, [], [], [0n]);
      }, /Device signature verification failed/);
    });

    it("should verify with nonce of varying lengths", async () => {
      const mockData = await generateMockData({
        circuitParams: [2048, 2000, 6, 50, 128],
      });

      const devicePrivateKey = mockData.devicePrivateKey;

      const nonces = [
        "short",
        "medium-length-nonce",
        "a-very-long-nonce-that-should-still-work-with-the-circuit-parameters",
      ];

      for (const nonce of nonces) {
        if (nonce.length <= 256) {
          const deviceSignature = signDeviceNonce(nonce, devicePrivateKey);
          const params = generateShowCircuitParams(mockData.circuitParams);
          const inputs = generateShowInputs(params, nonce, deviceSignature, mockData.deviceKey, [], [], [0n]);
          await bindPredicateName(inputs, 0, 0, "name");

          const witness = await circuit.calculateWitness(inputs);
          await circuit.expectConstraintPass(witness);
        }
      }
    });
  });

  describe("Integration with JWT Circuit", () => {
    it("should use device binding key from JWT circuit output", async () => {
      const mockData = await generateMockData({
        circuitParams: [2048, 2000, 6, 50, 128],
      });

      const deviceKeyX = base64ToBigInt(base64urlToBase64(mockData.deviceKey.x));
      const deviceKeyY = base64ToBigInt(base64urlToBase64(mockData.deviceKey.y));

      assert.ok(deviceKeyX > 0n, "Device key X should be valid");
      assert.ok(deviceKeyY > 0n, "Device key Y should be valid");

      const verifierNonce = "verifier-challenge-2024";
      const deviceSignature = signDeviceNonce(verifierNonce, mockData.devicePrivateKey);

      const params = generateShowCircuitParams(mockData.circuitParams);
      const inputs = generateShowInputs(params, verifierNonce, deviceSignature, mockData.deviceKey, [], [], [0n]);
      await bindPredicateName(inputs, 0, 0, "name");

      const witness = await circuit.calculateWitness(inputs);
      await circuit.expectConstraintPass(witness);

      assert.strictEqual(inputs.deviceKeyX, deviceKeyX, "Device key X should match");
      assert.strictEqual(inputs.deviceKeyY, deviceKeyY, "Device key Y should match");
    });

    it("should evaluate OR and NOT over predicate results", async () => {
      // Example postfix expression:
      //   pred0 pred1 NOT OR
      // Equivalent boolean expression: pred0 OR (NOT pred1)
      // Here predicateResults = [0, 0], so the circuit evaluates:
      //   false OR (NOT false) => true.
      const mockData = await generateMockData({
        circuitParams: [2048, 2000, 6, 50, 128],
      });

      const verifierNonce = "logic-expression-check";
      const deviceSignature = signDeviceNonce(verifierNonce, mockData.devicePrivateKey);

      const params = generateShowCircuitParams(mockData.circuitParams);
      const inputs = generateShowInputs(
        params,
        verifierNonce,
        deviceSignature,
        mockData.deviceKey,
        [],
        [predicateToken(0), predicateToken(1), LogicToken.NOT, LogicToken.OR],
        [0n, 0n]
      );

      inputs.predicateLen = 2n;
      inputs.predicateClaimRefs[0] = 0n;
      inputs.predicateOps[0] = 2n;
      inputs.predicateRhsValues[0] = 1n;
      inputs.predicateClaimRefs[1] = 1n;
      inputs.predicateOps[1] = 2n;
      inputs.predicateRhsValues[1] = 1n;
      await bindPredicateName(inputs, 0, 0, "claim_a");
      await bindPredicateName(inputs, 1, 1, "claim_b");

      const witness = await circuit.calculateWitness(inputs);
      await circuit.expectConstraintPass(witness);

      const signals = await circuit.readWitnessSignals(witness, ["expressionResult"]);
      assert.strictEqual(signals.expressionResult, 1n, "Expected pred0 OR NOT pred1 to evaluate to 1");
    });
  });

  describe("Age Verification via Generalized Predicates", () => {
    // As-of 2026-03-31, age >= 18 is equivalent to birth_roc_date <= 970331.
    const age18CutoffRoc = 970331n;

    function encodeClaim(claimKey: string, claimValue: string): string {
      return Buffer.from(JSON.stringify(["salt", claimKey, claimValue]), "utf8").toString("base64url");
    }

    it("returns true for age >= 18 (adult ROC birthday)", async () => {
      const mockData = await generateMockData({
        circuitParams: [2048, 2000, 6, 50, 128],
      });

      const verifierNonce = "age-check-adult";
      const deviceSignature = signDeviceNonce(verifierNonce, mockData.devicePrivateKey);

      const adultClaim = encodeClaim("roc_birthday", "0570605");
      const params = generateShowCircuitParams(mockData.circuitParams);
      const inputs = generateShowInputs(params, verifierNonce, deviceSignature, mockData.deviceKey, [adultClaim], [], [570605n]);
      await bindPredicateName(inputs, 0, 0, "roc_birthday");

      // pred0: claimValue <= 970331
      inputs.predicateOps[0] = 0n;
      inputs.predicateRhsValues[0] = age18CutoffRoc;

      const witness = await circuit.calculateWitness(inputs);
      await circuit.expectConstraintPass(witness);

      const signals = await circuit.readWitnessSignals(witness, ["expressionResult"]);
      assert.strictEqual(signals.expressionResult, 1n, "Expected adult claim to satisfy age >= 18");
    });

    it("returns false for age < 18 (underage ROC birthday)", async () => {
      const mockData = await generateMockData({
        circuitParams: [2048, 2000, 6, 50, 128],
      });

      const verifierNonce = "age-check-underage";
      const deviceSignature = signDeviceNonce(verifierNonce, mockData.devicePrivateKey);

      const underageClaim = encodeClaim("roc_birthday", "1040605");
      const params = generateShowCircuitParams(mockData.circuitParams);
      const inputs = generateShowInputs(params, verifierNonce, deviceSignature, mockData.deviceKey, [underageClaim], [], [1040605n]);
      await bindPredicateName(inputs, 0, 0, "roc_birthday");

      // pred0: claimValue <= 970331
      inputs.predicateOps[0] = 0n;
      inputs.predicateRhsValues[0] = age18CutoffRoc;

      const witness = await circuit.calculateWitness(inputs);
      await circuit.expectConstraintPass(witness);

      const signals = await circuit.readWitnessSignals(witness, ["expressionResult"]);
      assert.strictEqual(signals.expressionResult, 0n, "Expected underage claim to fail age >= 18");
    });
  });

  describe("Numeric Claim Verification via Generalized Predicates", () => {
    function encodeClaim(claimKey: string, claimValue: string): string {
      return Buffer.from(JSON.stringify(["salt", claimKey, claimValue]), "utf8").toString("base64url");
    }

    it("returns true for numeric score >= threshold", async () => {
      const mockData = await generateMockData({
        circuitParams: [2048, 2000, 6, 50, 128],
      });

      const verifierNonce = "numeric-score-check";
      const deviceSignature = signDeviceNonce(verifierNonce, mockData.devicePrivateKey);

      const scoreClaim = encodeClaim("score", "12345");
      const params = generateShowCircuitParams(mockData.circuitParams);
      const inputs = generateShowInputs(params, verifierNonce, deviceSignature, mockData.deviceKey, [scoreClaim], [], [12345n]);
      await bindPredicateName(inputs, 0, 0, "score");

      // pred0: claimValue >= 10000
      inputs.predicateOps[0] = 1n;
      inputs.predicateRhsValues[0] = 10000n;

      const witness = await circuit.calculateWitness(inputs);
      await circuit.expectConstraintPass(witness);

      const signals = await circuit.readWitnessSignals(witness, ["expressionResult"]);
      assert.strictEqual(signals.expressionResult, 1n, "Expected numeric claim to satisfy score >= 10000");
    });
  });

  describe("String and Boolean Claim Verification", () => {
    function encodeClaim(claimKey: string, claimValue: string): string {
      return Buffer.from(JSON.stringify(["salt", claimKey, claimValue]), "utf8").toString("base64url");
    }

    function packAsciiBigEndian(text: string): bigint {
      return Array.from(text).reduce((acc, ch) => acc * 256n + BigInt(ch.charCodeAt(0)), 0n);
    }

    it("returns true for packed string equality", async () => {
      const mockData = await generateMockData({
        circuitParams: [2048, 2000, 6, 50, 128],
      });

      const verifierNonce = "string-claim-check";
      const deviceSignature = signDeviceNonce(verifierNonce, mockData.devicePrivateKey);

      const packedNationality = packAsciiBigEndian("TW");
      const nationalityClaim = encodeClaim("nationality", packedNationality.toString());

      const params = generateShowCircuitParams(mockData.circuitParams);
      const inputs = generateShowInputs(params, verifierNonce, deviceSignature, mockData.deviceKey, [nationalityClaim], [], [packedNationality]);
      await bindPredicateName(inputs, 0, 0, "nationality");

      // pred0: claimValue == pack("TW")
      inputs.predicateOps[0] = 2n;
      inputs.predicateRhsValues[0] = packedNationality;

      const witness = await circuit.calculateWitness(inputs);
      await circuit.expectConstraintPass(witness);

      const signals = await circuit.readWitnessSignals(witness, ["expressionResult"]);
      assert.strictEqual(signals.expressionResult, 1n, "Expected packed string claim to match");
    });

    it("returns true for boolean equality", async () => {
      const mockData = await generateMockData({
        circuitParams: [2048, 2000, 6, 50, 128],
      });

      const verifierNonce = "boolean-claim-check";
      const deviceSignature = signDeviceNonce(verifierNonce, mockData.devicePrivateKey);

      const boolClaim = encodeClaim("is_over_18", "1");

      const params = generateShowCircuitParams(mockData.circuitParams);
      const inputs = generateShowInputs(params, verifierNonce, deviceSignature, mockData.deviceKey, [boolClaim], [], [1n]);
      await bindPredicateName(inputs, 0, 0, "is_over_18");

      // pred0: claimValue == 1
      inputs.predicateOps[0] = 2n;
      inputs.predicateRhsValues[0] = 1n;

      const witness = await circuit.calculateWitness(inputs);
      await circuit.expectConstraintPass(witness);

      const signals = await circuit.readWitnessSignals(witness, ["expressionResult"]);
      assert.strictEqual(signals.expressionResult, 1n, "Expected boolean claim to equal true");
    });
  });

  describe("Multi-Claim Predicate Evaluation", () => {
    function encodeClaim(claimKey: string, claimValue: string): string {
      return Buffer.from(JSON.stringify(["salt", claimKey, claimValue]), "utf8").toString("base64url");
    }

    it("returns true when two claims satisfy an AND expression", async () => {
      const mockData = await generateMockData({
        circuitParams: [2048, 2000, 6, 50, 128],
      });

      const verifierNonce = "multi-claim-and-check";
      const deviceSignature = signDeviceNonce(verifierNonce, mockData.devicePrivateKey);

      // claim0: roc_birthday = 0570605 (adult)
      // claim1: score = 12345
      const birthdayClaim = encodeClaim("roc_birthday", "0570605");
      const scoreClaim = encodeClaim("score", "12345");
      const params = generateShowCircuitParams(mockData.circuitParams);
      const inputs = generateShowInputs(
        params,
        verifierNonce,
        deviceSignature,
        mockData.deviceKey,
        [birthdayClaim, scoreClaim],
        [],
        []
      );

      // pred0: claim[0] <= 970331  (age >= 18 as of 2026-03-31)
      inputs.predicateClaimRefs[0] = 0n;
      inputs.predicateOps[0] = 0n;
      inputs.predicateRhsValues[0] = 970331n;

      // pred1: claim[1] >= 10000
      inputs.predicateClaimRefs[1] = 1n;
      inputs.predicateOps[1] = 1n;
      inputs.predicateRhsValues[1] = 10000n;
      inputs.predicateLen = 2n;
      await bindPredicateName(inputs, 0, 0, "roc_birthday");
      await bindPredicateName(inputs, 1, 1, "score");

      // Expression: pred0 pred1 AND
      inputs.tokenTypes[0] = 0n;
      inputs.tokenValues[0] = 0n;
      inputs.tokenTypes[1] = 0n;
      inputs.tokenValues[1] = 1n;
      inputs.tokenTypes[2] = 1n;
      inputs.tokenValues[2] = 0n;
      inputs.exprLen = 3n;

      const witness = await circuit.calculateWitness(inputs);
      await circuit.expectConstraintPass(witness);

      const signals = await circuit.readWitnessSignals(witness, ["expressionResult"]);
      assert.strictEqual(signals.expressionResult, 1n, "Expected both predicates to hold under AND");
    });

    it("compares a claim value against another claim value within the same credential", async () => {
      const mockData = await generateMockData({
        circuitParams: [2048, 2000, 6, 50, 128],
      });

      const verifierNonce = "multi-claim-ref-rhs-check";
      const deviceSignature = signDeviceNonce(verifierNonce, mockData.devicePrivateKey);

      const claimA = encodeClaim("age_now", "25");
      const claimB = encodeClaim("required_age", "18");
      const params = generateShowCircuitParams(mockData.circuitParams);
      const inputs = generateShowInputs(
        params,
        verifierNonce,
        deviceSignature,
        mockData.deviceKey,
        [claimA, claimB],
        [],
        [25n, 18n]
      );

      // pred0: claim[0] >= claim[1]
      inputs.predicateLen = 1n;
      inputs.predicateClaimRefs[0] = 0n;
      inputs.predicateOps[0] = 1n;
      inputs.predicateRhsIsRef[0] = 1n;
      inputs.predicateRhsValues[0] = 1n;
      await bindPredicateName(inputs, 0, 0, "age_now");
      await bindPredicateRhsName(inputs, 0, 1, "required_age");

      // Expression: pred0
      inputs.tokenTypes[0] = 0n;
      inputs.tokenValues[0] = 0n;
      inputs.exprLen = 1n;

      const witness = await circuit.calculateWitness(inputs);
      await circuit.expectConstraintPass(witness);

      const signals = await circuit.readWitnessSignals(witness, ["expressionResult"]);
      assert.strictEqual(signals.expressionResult, 1n, "Expected claim[0] >= claim[1] to evaluate true");
    });

    it("accepts both encodedClaims and normalizedClaimValues when they agree", async () => {
      const mockData = await generateMockData({
        circuitParams: [2048, 2000, 6, 50, 128],
      });

      const verifierNonce = "dual-input-consistency";
      const deviceSignature = signDeviceNonce(verifierNonce, mockData.devicePrivateKey);

      const birthdayClaim = encodeClaim("roc_birthday", "0570605");
      const scoreClaim = encodeClaim("score", "12345");
      const params = generateShowCircuitParams(mockData.circuitParams);
      const inputs = generateShowInputs(
        params,
        verifierNonce,
        deviceSignature,
        mockData.deviceKey,
        [birthdayClaim, scoreClaim],
        [],
        [570605n, 12345n]
      );

      assert.deepStrictEqual(inputs.claimValues.slice(0, 2), [570605n, 12345n]);
    });

    it("rejects mismatched encodedClaims and normalizedClaimValues", async () => {
      const mockData = await generateMockData({
        circuitParams: [2048, 2000, 6, 50, 128],
      });

      const verifierNonce = "dual-input-mismatch";
      const deviceSignature = signDeviceNonce(verifierNonce, mockData.devicePrivateKey);

      const birthdayClaim = encodeClaim("roc_birthday", "0570605");
      const params = generateShowCircuitParams(mockData.circuitParams);

      assert.throws(() => {
        generateShowInputs(
          params,
          verifierNonce,
          deviceSignature,
          mockData.deviceKey,
          [birthdayClaim],
          [],
          [123n]
        );
      }, /must equal normalizedClaimValues\[0\]/);
    });
  });
});
