import type { WitnessTester } from "circomkit";
import { circomkit } from "../common/index.ts";
import { generateMockData } from "../../src/mock-vc-generator.ts";

describe("JWT Verifier", () => {
  let circuit!: WitnessTester<any, any>;

  describe("Mock SD-JWT credential", () => {
    const PARAMS = [2048, 2000, 4, 50, 128];

    before(async () => {
      circuit = await circomkit.WitnessTester(`JWT`, {
        file: "jwt",
        template: "JWT",
        params: PARAMS,
        recompile: true,
      });
      console.log("#constraints:", await circuit.getConstraintCount());
    });

    it("should verify a credential with two disclosures", async () => {
      const mockData = await generateMockData({ circuitParams: PARAMS });

      const witness = await circuit.calculateWitness(mockData.circuitInputs);
      await circuit.expectConstraintPass(witness);
    });
  });

  describe("Production-size credential", () => {
    const PARAMS = [1024 * 3, 2200, 8, 50, 128];

    before(async () => {
      circuit = await circomkit.WitnessTester(`JWT`, {
        file: "jwt",
        template: "JWT",
        params: PARAMS,
        recompile: true,
      });
      console.log("#constraints:", await circuit.getConstraintCount());
    });

    it("should verify a credential with six disclosures", async () => {
      const mockData = await generateMockData({
        circuitParams: PARAMS,
        targetPayloadLength: 1800,
        // Disclosures must be at least 56 bytes (two SHA-256 blocks in ClaimHasher).
        claims: [
          { key: "name", value: "Alice Wonderland" },
          { key: "roc_birthday", value: "0750101" },
          { key: "nationality", value: "Taiwan (ROC)" },
          { key: "id_number", value: "A123456789" },
          { key: "gender", value: "female-holder" },
          { key: "address", value: "Xinyi District, Taipei" },
        ],
      });

      const witness = await circuit.calculateWitness(mockData.circuitInputs);
      await circuit.expectConstraintPass(witness);
    });
  });
});
