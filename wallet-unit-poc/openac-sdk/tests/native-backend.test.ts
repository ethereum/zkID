import { describe, it, expect, beforeAll } from "vitest";
import { existsSync } from "fs";
import { readFile } from "fs/promises";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { WitnessCalculator } from "../src/witness-calculator.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const KEYS_DIR = join(__dirname, "..", "..", "ecdsa-spartan2", "keys");
const ASSETS_DIR = join(__dirname, "..", "assets");
const INPUTS_DIR = join(__dirname, "fixtures", "inputs");

const NATIVE_ARTIFACTS = [
  "prepare_proof.bin",
  "show_proof.bin",
  "prepare_instance.bin",
  "show_instance.bin",
  "prepare_witness.bin",
  "show_witness.bin",
  "shared_blinds.bin",
  "prepare_verifying.key",
  "show_verifying.key",
];

function hasNativeArtifacts(): boolean {
  return NATIVE_ARTIFACTS.every((f) => existsSync(join(KEYS_DIR, f)));
}

describe.skipIf(!hasNativeArtifacts())(
  "Native Backend: Artifact Existence",
  () => {
    it("should find pre-generated keys directory", () => {
      expect(existsSync(KEYS_DIR)).toBe(true);
    });

    it("should have all proof components", () => {
      for (const artifact of NATIVE_ARTIFACTS) {
        const path = join(KEYS_DIR, artifact);
        expect(existsSync(path), `${artifact} should exist`).toBe(true);
      }
    });
  },
);

describe("Age Verification", () => {
  let calculator: WitnessCalculator;

  beforeAll(async () => {
    calculator = new WitnessCalculator(ASSETS_DIR);
    await calculator.init();
  });

  it("should verify expression result from Show circuit witness", async () => {
    const inputJson = JSON.parse(
      await readFile(join(INPUTS_DIR, "show", "default.json"), "utf-8"),
    );

    const inputs: Record<string, unknown> = {
      deviceKeyX: BigInt(inputJson.deviceKeyX),
      deviceKeyY: BigInt(inputJson.deviceKeyY),
      sig_r: BigInt(inputJson.sig_r),
      sig_s_inverse: BigInt(inputJson.sig_s_inverse),
      messageHash: BigInt(inputJson.messageHash),
      predicateLen: BigInt(inputJson.predicateLen),
      claimValues: inputJson.claimValues.map((v: string) => BigInt(v)),
      claimIdentifierHashes: inputJson.claimIdentifierHashes.map((v: string) => BigInt(v)),
      predicateClaimNames: inputJson.predicateClaimNames.map((r: string[]) => r.map((v) => BigInt(v))),
      predicateClaimNameLens: inputJson.predicateClaimNameLens.map((v: string) => BigInt(v)),
      predicateRhsClaimNames: inputJson.predicateRhsClaimNames.map((r: string[]) => r.map((v) => BigInt(v))),
      predicateRhsClaimNameLens: inputJson.predicateRhsClaimNameLens.map((v: string) => BigInt(v)),
      predicateClaimRefs: inputJson.predicateClaimRefs.map((v: string) => BigInt(v)),
      predicateOps: inputJson.predicateOps.map((v: string) => BigInt(v)),
      predicateRhsIsRef: inputJson.predicateRhsIsRef.map((v: string) => BigInt(v)),
      predicateRhsValues: inputJson.predicateRhsValues.map((v: string) => BigInt(v)),
      tokenTypes: inputJson.tokenTypes.map((v: string) => BigInt(v)),
      tokenValues: inputJson.tokenValues.map((v: string) => BigInt(v)),
      exprLen: BigInt(inputJson.exprLen),
      issuerKeyX: BigInt(inputJson.issuerKeyX),
      issuerKeyY: BigInt(inputJson.issuerKeyY),
      issuerTreeDepth: BigInt(inputJson.issuerTreeDepth),
      issuerTreeIndex: BigInt(inputJson.issuerTreeIndex),
      issuerTreeSiblings: inputJson.issuerTreeSiblings.map((r: string[]) => r.map((v) => BigInt(v))),
    };

    const witness = await calculator.calculateShowWitness(inputs);

    // w[1] = expressionResult (predicate evaluation result)
    expect(typeof witness[1]).toBe("bigint");
  }, 30_000);
});
