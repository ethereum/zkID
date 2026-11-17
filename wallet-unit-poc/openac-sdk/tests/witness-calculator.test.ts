import { describe, it, expect, beforeAll } from "vitest";
import { readFile } from "fs/promises";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { WitnessCalculator } from "../src/witness-calculator.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ASSETS_DIR = join(__dirname, "..", "assets");
const INPUTS_DIR = join(__dirname, "fixtures", "inputs");

// Circuit input JSON stores field elements as decimal strings.
function withBigInts(json: Record<string, unknown>): Record<string, unknown> {
  return JSON.parse(JSON.stringify(json), (_k, v) =>
    typeof v === "string" && /^\d+$/.test(v) ? BigInt(v) : v,
  );
}

describe("WitnessCalculator", () => {
  let calculator: WitnessCalculator;

  beforeAll(async () => {
    calculator = new WitnessCalculator(ASSETS_DIR);
    await calculator.init();
  });

  describe("Show circuit witness generation", () => {
    it("should generate a valid witness from default show inputs", async () => {
      const inputJson = JSON.parse(
        await readFile(join(INPUTS_DIR, "show", "default.json"), "utf-8"),
      );

      const inputs = withBigInts(inputJson);

      const witness = await calculator.calculateShowWitness(inputs);

      expect(witness[0]).toBe(1n);
      // w[1] = expressionResult, w[2..=3] = issuerRoot[hi, lo], w[4..=5] =
      // revocationRoot, w[6..=160] = messageHash + predicate program, then the
      // private device key at w[161]/[162].
      expect(witness[2] + witness[3]).not.toBe(0n);
      expect(witness[4] + witness[5]).not.toBe(0n);
      expect(witness[6]).toBe(BigInt(inputJson.messageHash));
      expect(witness[161]).toBe(BigInt(inputJson.deviceKeyX));
      expect(witness[162]).toBe(BigInt(inputJson.deviceKeyY));
    }, 30_000);

    it("should generate WTNS binary from show inputs", async () => {
      const inputJson = JSON.parse(
        await readFile(join(INPUTS_DIR, "show", "default.json"), "utf-8"),
      );

      const inputs = withBigInts(inputJson);

      const wtns = await calculator.calculateShowWitnessWtns(inputs);

      expect(wtns[0]).toBe("w".charCodeAt(0));
      expect(wtns[1]).toBe("t".charCodeAt(0));
      expect(wtns[2]).toBe("n".charCodeAt(0));
      expect(wtns[3]).toBe("s".charCodeAt(0));
    }, 30_000);
  });

  describe("JWT circuit witness generation", () => {
    it("should generate a valid witness from default jwt inputs", async () => {
      const inputJson = JSON.parse(
        await readFile(join(INPUTS_DIR, "jwt", "default.json"), "utf-8"),
      );

      const witness = await calculator.calculateJwtWitness(inputJson);

      expect(witness[0]).toBe(1n);
      // JWT circuit (maxMatches=4): w[1..2] = normalizedClaimValues, w[3] = KeyBindingX, w[4] = KeyBindingY
      expect(witness.length).toBeGreaterThan(4);
    }, 120_000);
  });
});
