/**
 * Validity-period check in CertChainRSA256.
 *
 * The circuit walks the DER structure to the Validity field (no prover-supplied
 * offset) and asserts notBefore <= currentTime <= notAfter. Each test builds a
 * synthetic TBS signed by a throwaway CA and varies one field.
 */
import { WitnessTester } from "circomkit";
import { circomkit } from "../common";
import {
  buildTbs,
  chainInputs,
  makeTestCa,
  makeUserSpki,
  name,
  type TbsOptions,
  type TestCa,
} from "../common/testCert";

// 2026-11-14 15:59:59 UTC as YYMMDDHHMMSS.
const NOW = 261114155959n;

describe("CertChainRSA256 validity period", function () {
  let circuit: WitnessTester;
  let ca: TestCa;
  let spki: Buffer;

  before(async function () {
    this.timeout(900_000);
    ca = makeTestCa();
    spki = makeUserSpki();
    circuit = await circomkit.WitnessTester("certChainValidity", {
      file: "certChain",
      template: "CertChainRSA256",
      params: [1536, 121, 17, 2048, 17, 2048, 128, 20],
    });
  });

  function inputs(opts: Omit<TbsOptions, "spki">, currentTime = NOW) {
    return chainInputs(ca, buildTbs({ ...opts, spki }), currentTime);
  }

  async function accepts(input: Record<string, any>) {
    const witness = await circuit.calculateWitness(input as any);
    await circuit.expectConstraintPass(witness);
  }

  describe("accepts", function () {
    it("a certificate inside its validity period", async function () {
      await accepts(inputs({}));
    });

    it("currentTime equal to notAfter", async function () {
      await accepts(inputs({ notAfter: "261114155959Z" }));
    });

    it("currentTime equal to notBefore", async function () {
      await accepts(inputs({ notBefore: "261114155959Z" }));
    });

    it("a 1-byte serial number", async function () {
      await accepts(inputs({ serial: Buffer.from([0x05]) }));
    });

    it("a 20-byte serial number", async function () {
      await accepts(inputs({ serial: Buffer.alloc(20, 0x11) }));
    });

    it("an issuer name of 127 content bytes", async function () {
      // C (13) + OU (11 + 60) + OU (11 + 14) + CN (11 + 7) = 127.
      const issuer = name("Test CA", [60, 14]);
      if (issuer.length !== 2 + 127) {
        throw new Error(`unexpected issuer length ${issuer.length}`);
      }
      await accepts(inputs({ issuer }));
    });
  });

  describe("rejects", function () {
    it("a certificate that expired one second ago", async function () {
      await circuit.expectFail(inputs({ notAfter: "261114155958Z" }) as any);
    });

    it("a certificate that becomes valid one second from now", async function () {
      await circuit.expectFail(inputs({ notBefore: "261114160000Z" }) as any);
    });

    it("a GeneralizedTime notAfter (2050 or later)", async function () {
      await circuit.expectFail(inputs({ notAfter: "20510101000000Z" }) as any);
    });

    it("a GeneralizedTime notBefore", async function () {
      await circuit.expectFail(inputs({ notBefore: "20260101000000Z" }) as any);
    });

    it("a notAfter in 19YY (UTCTime year 50..99)", async function () {
      await circuit.expectFail(inputs({ notAfter: "991231235959Z" }) as any);
    });

    it("an issuer name of 128 or more content bytes (long-form length)", async function () {
      await circuit.expectFail(inputs({ issuer: name("Test CA", [60, 60, 60]) }) as any);
    });

    it("a TBS without the v3 version block", async function () {
      await circuit.expectFail(inputs({ version: false }) as any);
    });

    it("a currentTime that does not fit in 40 bits", async function () {
      await circuit.expectFail(inputs({}, NOW + (1n << 40n)) as any);
    });
  });
});
