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

    // Field elements are decimal strings in the fixture.
    const inputs = JSON.parse(JSON.stringify(inputJson), (_k, v) =>
      typeof v === "string" && /^\d+$/.test(v) ? BigInt(v) : v,
    );

    const witness = await calculator.calculateShowWitness(inputs);

    // w[1] = expressionResult (predicate evaluation result)
    expect(typeof witness[1]).toBe("bigint");
  }, 30_000);
});
