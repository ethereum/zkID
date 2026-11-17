import { describe, it, expect, beforeAll } from "vitest";
import { readFile } from "fs/promises";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { WitnessCalculator } from "../src/witness-calculator.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ASSETS_DIR = join(__dirname, "..", "assets");
const INPUTS_DIR = join(__dirname, "fixtures", "inputs");

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

      expect(witness[0]).toBe(1n);
      // w[1] = expressionResult, w[2..=3] = issuerRoot[hi, lo], w[4..=158] =
      // messageHash + predicate program; the private device key follows.
      expect(witness[4]).toBe(BigInt(inputJson.messageHash));
      expect(witness[159]).toBe(BigInt(inputJson.deviceKeyX));
      expect(witness[160]).toBe(BigInt(inputJson.deviceKeyY));
    }, 30_000);

    it("should generate WTNS binary from show inputs", async () => {
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
