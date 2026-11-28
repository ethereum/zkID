import type { WitnessTester } from "circomkit";
import { circomkit } from "../common/index.ts";
import { generateMockData } from "../../src/mock-vc-generator.ts";
import { generateShowCircuitParams, generateShowInputs, signDeviceNonce } from "../../src/show.ts";
import { bindPredicateName } from "../common/claim-identity.ts";
import { witnessIndices } from "../common/witness-signals.ts";
import { buildRevocationWitness, createRevocationRegistry, toLimbs, bytesToBigInt } from "../../src/revocation.ts";
import { DEFAULT_TEST_ISSUER, buildIssuerRegistry, generateIssuerMembershipInputs } from "../../src/issuer-hiding.ts";
import { base64urlToBigInt } from "../../src/utils.ts";
import { randomBytes } from "crypto";
import assert from "assert";
import { p256 } from "@noble/curves/nist.js";

const REVOCATION_MAX_DEPTH = 4;

describe("Complete Flow: Register (JWT) → Show Circuit", () => {
  let jwtCircuit: WitnessTester<
    [
      "message",
      "messageLength",
      "periodIndex",
      "sig_r",
      "sig_s_inverse",
      "pubKeyX",
      "pubKeyY",
      "matchesCount",
      "matchSubstring",
      "matchLength",
      "matchIndex",
      "claims",
      "claimLengths",
      "decodeFlags",
      "claimFormats"
    ],
    ["KeyBindingX", "KeyBindingY", "normalizedClaimValues"]
  >;

  let showCircuit: WitnessTester<
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
    []
  >;

  before(async () => {
    const RECOMPILE = true;
    jwtCircuit = await circomkit.WitnessTester(`JWT`, {
      file: "jwt",
      template: "JWT",
      params: [1920, 1600, 4, 50, 128],
      recompile: RECOMPILE,
    });
    console.log("JWT Circuit #constraints:", await jwtCircuit.getConstraintCount());
    showCircuit = await circomkit.WitnessTester(`Show`, {
      file: "show",
      template: "Show",
      params: [2, 2, 8, 64, 8, REVOCATION_MAX_DEPTH],
      recompile: RECOMPILE,
    });
    console.log("Show Circuit #constraints:", await showCircuit.getConstraintCount());
  });

  describe("Complete End-to-End Flow", () => {
    it("should pass full flow: JWT normalized claim -> Show predicate evaluation", async () => {
      const mockData = await generateMockData({
        circuitParams: [1920, 1600, 4, 50, 128],
        claims: [{ key: "roc_birthday", value: "0570605" }],
      });

      const jwtWitness = await jwtCircuit.calculateWitness(mockData.circuitInputs);
      await jwtCircuit.expectConstraintPass(jwtWitness);
      const normalizedClaimValues = [570605n, 0n];

      const verifierNonce = "full-flow-predicate-check";
      const deviceSignature = signDeviceNonce(verifierNonce, mockData.devicePrivateKey);
      const showParams = generateShowCircuitParams(mockData.circuitParams);
      // Issuer hiding: Show proves the credential's issuer is in a registry of
      // several issuers and outputs only that registry's root.
      const issuer = {
        x: base64urlToBigInt(mockData.issuerKey.x),
        y: base64urlToBigInt(mockData.issuerKey.y),
      };
      const issuerRegistry = buildIssuerRegistry([DEFAULT_TEST_ISSUER, issuer]);
      const showInputs = generateShowInputs(
        showParams,
        verifierNonce,
        deviceSignature,
        mockData.deviceKey,
        [],
        [],
        normalizedClaimValues,
        undefined,
        generateIssuerMembershipInputs(issuer, issuerRegistry),
      );

      showInputs.predicateLen = 1n;
      showInputs.predicateClaimRefs[0] = 0n;
      showInputs.predicateOps[0] = 0n;
      showInputs.predicateRhsValues[0] = 1070101n;
      showInputs.tokenTypes[0] = 0n;
      showInputs.tokenValues[0] = 0n;
      showInputs.exprLen = 1n;
      await bindPredicateName(showInputs, 0, 0, "roc_birthday");

      // The revocation value Show proves against is the one the JWT circuit extracted.
      const [hi, lo] = await witnessIndices(jwtCircuit, [
        "main.RevocationValue[0]",
        "main.RevocationValue[1]",
      ]);
      const registry = createRevocationRegistry(Array.from({ length: 5 }, () => bytesToBigInt(randomBytes(32))));
      const revocation = buildRevocationWitness(issuer, mockData.revocationValue, registry, REVOCATION_MAX_DEPTH);
      revocation.revocationValue = [jwtWitness[hi], jwtWitness[lo]];

      // The Show .sym is too large for circomkit's output check, so read the outputs by index.
      const showWitness = await showCircuit.calculateWitness({ ...showInputs, ...revocation });
      await showCircuit.expectConstraintPass(showWitness);
      const outputs = await witnessIndices(showCircuit, [
        "main.expressionResult",
        "main.issuerRoot[0]",
        "main.issuerRoot[1]",
        "main.revocationRoot[0]",
        "main.revocationRoot[1]",
      ]);
      assert.deepStrictEqual(
        outputs.map((i) => showWitness[i]),
        [1n, ...toLimbs(issuerRegistry.root), ...toLimbs(registry.root)],
      );
    });

    // it("should complete full flow: JWT circuit extracts device key → Show circuit verifies device signature", async () => {
    //   const mockData = await generateMockData({
    //     circuitParams: [1920, 1900, 4, 50, 128],
    //     decodeFlags: [0, 1],
    //     // issuer: "did:key:test-issuer",
    //     // subject: "did:key:test-subject",
    //   });

    //   fs.writeFileSync("inputs/jwt/default.json", JSON.stringify(mockData.circuitInputs, null, 2));
    //   const jwtWitness = await jwtCircuit.calculateWitness(mockData.circuitInputs);
    //   await jwtCircuit.expectConstraintPass(jwtWitness);

    //   // const jwtOutputs = await jwtCircuit.readWitnessSignals(jwtWitness, ["KeyBindingX", "KeyBindingY"]);
    //   // Get circuit outputs
    //   // const outputs = await circuit.readWitnessSignals(witness, ["KeyBindingX", "KeyBindingY"]);
    //   // TODO: readWitnessSignals is not returning outputs from Circom (bug in circomkit)
    //   // Verified locally using Circomkit logging
    //   // Need to find a more efficient way to retrieve outputs from Circom
    //   // Large witness values are causing overflow issues
    //   // readWitnessSignal works fine for smaller witnesses

    //   // const extractedKeyBindingX = jwtOutputs.KeyBindingX as bigint;
    //   // const extractedKeyBindingY = jwtOutputs.KeyBindingY as bigint;

    //   const expectedKeyX = base64ToBigInt(base64urlToBase64(mockData.deviceKey.x));
    //   const expectedKeyY = base64ToBigInt(base64urlToBase64(mockData.deviceKey.y));

    //   // assert.strictEqual(extractedKeyBindingX, expectedKeyX);
    //   // assert.strictEqual(extractedKeyBindingY, expectedKeyY);

    //   let claim = mockData.claims[mockData.circuitInputs.ageClaimIndex - 2];

    //   const verifierNonce = "verifier-challenge-" + Date.now().toString();
    //   const deviceSignature = signDeviceNonce(verifierNonce, mockData.devicePrivateKey);

    //   const showParams = generateShowCircuitParams([128]);
    //   const showInputs = generateShowInputs(showParams, verifierNonce, deviceSignature, mockData.deviceKey, claim);

    //   fs.writeFileSync("inputs/show/default.json", JSON.stringify(showInputs, null, 2));

    //   // assert.strictEqual(showInputs.deviceKeyX, expectedKeyX);
    //   // assert.strictEqual(showInputs.deviceKeyY, expectedKeyY);

    //   const showWitness = await showCircuit.calculateWitness(showInputs);
    //   await showCircuit.expectConstraintPass(showWitness);
    // });

    it("should fail Show circuit when device signature doesn't match extracted key", async () => {
      const mockData = await generateMockData({
        circuitParams: [1920, 1600, 4, 50, 128],
      });

      const jwtWitness = await jwtCircuit.calculateWitness(mockData.circuitInputs);
      await jwtCircuit.expectConstraintPass(jwtWitness);

      const verifierNonce = "verifier-challenge-12345";
      const wrongPrivateKey = p256.utils.randomSecretKey();
      const wrongSignature = signDeviceNonce(verifierNonce, wrongPrivateKey);

      const showParams = {
        nClaims: 2,
        maxPredicates: 2,
        maxLogicTokens: 8,
        valueBits: 64,
        maxIssuerDepth: 8,
      };

      assert.throws(
        () => {
          generateShowInputs(showParams, verifierNonce, wrongSignature, mockData.deviceKey, [mockData.claims[0]]);
        },
        /Device signature verification failed/,
        "Should fail when device signature doesn't match device binding key"
      );
    });
  });
});
