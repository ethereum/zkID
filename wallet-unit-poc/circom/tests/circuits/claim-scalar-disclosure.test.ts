import assert from "assert";
import type { WitnessTester } from "circomkit";
import { circomkit } from "../common/index.ts";

const DECODED_LEN = 64;

function claimBytes(value: string): number[] {
  const bytes = Array.from(new TextEncoder().encode(value));
  assert.ok(bytes.length <= DECODED_LEN);
  return [...bytes, ...Array(DECODED_LEN - bytes.length).fill(0)];
}

describe("ClaimValueExtractor scalar disclosure shape", () => {
  let circuit: WitnessTester<["claim", "isActive"], ["value", "valueLength"]>;

  before(async () => {
    circuit = await circomkit.WitnessTester("ClaimScalarDisclosure", {
      file: "components/claim-value-extractor",
      template: "ClaimValueExtractor",
      params: [DECODED_LEN],
      recompile: true,
    });
  });

  for (const disclosure of [
    '["salt","age",["18"]]',
    '["salt","age",{"18":0}]',
    '["salt","age",true,"18"]',
    '["salt","age","18",0]',
    '[["salt"],"age","18"]',
    '["salt",["age"],"18"]',
  ]) {
    it(`rejects ${disclosure}`, async () => {
      await circuit.expectFail({ claim: claimBytes(disclosure), isActive: 1 });
    });
  }

  for (const disclosure of [
    '["salt","age","18"]',
    '[ "salt" , "age" , "18" ]',
    ' \n["salt", "age", "18"] \t',
    '["salt","name","Doe, Jane"]',
  ]) {
    it(`accepts ${disclosure}`, async () => {
      const witness = await circuit.calculateWitness({ claim: claimBytes(disclosure), isActive: 1 });
      await circuit.expectConstraintPass(witness);
      const { value, valueLength } = await circuit.readWitnessSignals(witness, ["value", "valueLength"]);
      const actual = (value as bigint[])
        .slice(0, Number(valueLength))
        .map((byte) => String.fromCharCode(Number(byte)))
        .join("");
      assert.strictEqual(actual, JSON.parse(disclosure)[2]);
    });
  }

  it("does not constrain inactive disclosure slots", async () => {
    const witness = await circuit.calculateWitness({
      claim: claimBytes('["salt","age",["18"]]'),
      isActive: 0,
    });
    await circuit.expectConstraintPass(witness);
  });
});
