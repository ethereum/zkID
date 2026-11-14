import { WitnessTester } from "circomkit";
import { circomkit } from "../common";
import { loadInput } from "../common/fixtures";

describe("CertChainRSA256 (rs4096)", function () {
  let circuit: WitnessTester<
    [
      "tbsModulusTagOffset",
      "issuerTbs",
      "issuerTbsLength",
      "actualIssuerTbsLength",
      "issuerRsaModulus",
      "issuerRsaSignature",
      "smtRoot",
      "serialNumber",
      "smtSiblings",
      "smtOldKey",
      "smtOldValue",
      "smtIsOld0",
      "currentTime",
      "pkBlind",
    ],
    ["pkCommit"]
  >;
  let input: Record<string, any>;

  before(async function () {
    this.timeout(900_000);
    input = loadInput("cert_chain_rs4096");
    circuit = await circomkit.WitnessTester("certChainRS4096", {
      file: "certChain",
      template: "CertChainRSA256",
      params: [1536, 121, 34, 4096, 17, 2048, 128, 20],
    });
  });

  it("should accept valid cert chain inputs", async function () {
    this.timeout(900_000);
    const witness = await circuit.calculateWitness(input as any);
    await circuit.expectConstraintPass(witness);
  });

  it("should reject a currentTime outside the validity period", async function () {
    this.timeout(900_000);
    // Later than any notAfter that fits UTCTime (YY < 50).
    await circuit.expectFail({ ...input, currentTime: 491231235959n } as any);
    // Earlier than the fixture's notBefore.
    await circuit.expectFail({ ...input, currentTime: 200101000000n } as any);
  });

  it("should reject a currentTime that does not fit in 40 bits", async function () {
    this.timeout(900_000);
    await circuit.expectFail({
      ...input,
      currentTime: (input.currentTime as bigint) + (1n << 40n),
    } as any);
  });
});
