/**
 * keyUsage check in CertChainRSA256.
 *
 * MOICA issues each card a signing certificate (keyUsage digitalSignature) and
 * an encryption certificate (keyEncipherment + dataEncipherment) over separate
 * keys. Both are signed by the same CA and are otherwise identical, and the
 * card performs a private-key operation with either key, so without this
 * check one card yields two nullifiers per app.
 */
import { WitnessTester } from "circomkit";
import { circomkit } from "../common";
import {
  AUTHORITY_KEY_ID,
  buildTbs,
  chainInputs,
  keyUsage,
  KEY_USAGE_ENCRYPTION,
  KEY_USAGE_SIGNING,
  makeTestCa,
  makeUserSpki,
  SUBJECT_KEY_ID,
  type TbsOptions,
  type TestCa,
} from "../common/testCert";

const NOW = 261114155959n;

describe("CertChainRSA256 keyUsage", function () {
  let circuit: WitnessTester;
  let ca: TestCa;
  let spki: Buffer;

  before(async function () {
    this.timeout(900_000);
    ca = makeTestCa();
    spki = makeUserSpki();
    circuit = await circomkit.WitnessTester("certChainKeyUsage", {
      file: "certChain",
      template: "CertChainRSA256",
      params: [1536, 121, 17, 2048, 17, 2048, 128, 20],
    });
  });

  function inputs(opts: Partial<TbsOptions>) {
    return chainInputs(ca, buildTbs({ spki, ...opts }), NOW);
  }

  it("accepts a signing certificate (digitalSignature)", async function () {
    const witness = await circuit.calculateWitness(inputs({}) as any);
    await circuit.expectConstraintPass(witness);
  });

  describe("rejects", function () {
    it("an encryption certificate (keyEncipherment + dataEncipherment)", async function () {
      await circuit.expectFail(
        inputs({
          leadingExtensions: [AUTHORITY_KEY_ID, SUBJECT_KEY_ID, KEY_USAGE_ENCRYPTION],
        }) as any
      );
    });

    it("digitalSignature combined with another usage", async function () {
      // 06 c0: digitalSignature + nonRepudiation.
      await circuit.expectFail(
        inputs({
          leadingExtensions: [AUTHORITY_KEY_ID, SUBJECT_KEY_ID, keyUsage("06c0")],
        }) as any
      );
    });

    it("a certificate with no keyUsage extension", async function () {
      await circuit.expectFail(
        inputs({ leadingExtensions: [AUTHORITY_KEY_ID, SUBJECT_KEY_ID] }) as any
      );
    });

    it("keyUsage in a different position", async function () {
      await circuit.expectFail(
        inputs({
          leadingExtensions: [KEY_USAGE_SIGNING, AUTHORITY_KEY_ID, SUBJECT_KEY_ID],
        }) as any
      );
    });

    it("a TBS truncated inside keyUsage, completed by the SHA-256 padding byte", async function () {
      // The last keyUsage byte is 0x80, the same as the first SHA-256 padding
      // byte. A TBS cut just before it must not pass by reading the padding.
      const full = buildTbs({ spki });
      const usage = Buffer.from("300e0603551d0f0101ff040403020780", "hex");
      const cut = full.indexOf(usage) + usage.length - 1;
      const truncated = Buffer.from(full.subarray(0, cut));
      truncated.writeUInt16BE(cut - 4, 2);
      await circuit.expectFail(chainInputs(ca, truncated, NOW) as any);
    });

    it("a signing keyUsage placed after an encryption keyUsage", async function () {
      // Not valid X.509 (duplicate extension), but shows the circuit reads the
      // structural position rather than searching for a matching pattern.
      await circuit.expectFail(
        inputs({
          leadingExtensions: [AUTHORITY_KEY_ID, SUBJECT_KEY_ID, KEY_USAGE_ENCRYPTION],
          extraExtensions: [KEY_USAGE_SIGNING],
        }) as any
      );
    });
  });
});
