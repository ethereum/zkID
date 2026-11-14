/**
 * Audit v2 regression suite — see `wallet-unit-poc/circom/audit_report_v2.md`.
 *
 * Each describe block locks in the fix for one finding: the bypass scenario
 * the audit recreates is asserted to be rejected by the wrapper circuit.
 * A test passes when the corresponding constraint holds; it fails when the
 * fix regresses. Baselines guard against over-tightening.
 */
import { WitnessTester } from "circomkit";
import { circomkit } from "../common";
import { loadInput } from "../common/fixtures";
import assert from "node:assert";
import {
  constants as cryptoConstants,
  generateKeyPairSync,
  sign as cryptoSign,
  type KeyObject,
} from "node:crypto";
import { sha256Pad } from "@zk-email/helpers/dist/shaHash";
import {
  bigIntToChunkedBytes,
  bytesToBigInt,
} from "@zk-email/helpers/dist/binaryFormat";

const MAX_MESSAGE_LENGTH = 1536;
const MAX_SERIAL_LEN = 20;
const N_BITS = 121;
const K_LIMBS_USER = 17;
const USER_MODULUS_BITS = 2048;
const CHAIN_PARAMS = [
  MAX_MESSAGE_LENGTH,
  N_BITS,
  K_LIMBS_USER,
  USER_MODULUS_BITS,
  K_LIMBS_USER,
  USER_MODULUS_BITS,
  128,
  MAX_SERIAL_LEN,
];

type ChainInputs = [
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
  "pkBlind"
];

function findAlternateSerialOffsets(
  tbs: readonly bigint[],
  tbsLen: number
): { offset: number; target: bigint }[] {
  const out: { offset: number; target: bigint }[] = [];
  for (let i = 0; i + 2 < tbsLen; i++) {
    if (Number(tbs[i]) !== 0x02) continue;
    const L = Number(tbs[i + 1]);
    if (L <= 0 || L > MAX_SERIAL_LEN) continue;
    if (i + 2 + L > tbsLen) continue;
    let v = 0n;
    for (let j = 0; j < L; j++) v = v * 256n + tbs[i + 2 + j];
    out.push({ offset: i + 2, target: v });
  }
  return out;
}

function canonicalSerialOffset(tbs: readonly bigint[]): number {
  const hasVersion = Number(tbs[4]) === 0xa0;
  return 4 + (hasVersion ? 5 : 0) + 2;
}

describe("Audit v2 regression suite", function () {
  let chainCircuit: WitnessTester<ChainInputs, ["pkCommit"]>;
  let chainInput: Record<string, any>;

  before(async function () {
    this.timeout(900_000);
    chainInput = loadInput("cert_chain_rs2048");
    chainCircuit = await circomkit.WitnessTester("certChainRS2048", {
      file: "certChain",
      template: "CertChainRSA256",
      params: CHAIN_PARAMS,
    });
  });

  // Finding 1 (CRITICAL) — see audit_report_v2.md.
  describe("[CRITICAL] forged serialNumber is rejected by CertChainRSA256", function () {
    let alternates: { offset: number; target: bigint }[];

    before(function () {
      const tbsLen = Number(chainInput.actualIssuerTbsLength as bigint);
      alternates = findAlternateSerialOffsets(
        chainInput.issuerTbs as bigint[],
        tbsLen
      );
    });

    it("fixture's TBS contains alternate ASN.1 INTEGER offsets the audit warned about", function () {
      const realSerial = chainInput.serialNumber as bigint;
      const realOffset = canonicalSerialOffset(chainInput.issuerTbs as bigint[]);
      const realHit = alternates.find(
        (a) => a.offset === realOffset && a.target === realSerial
      );
      assert.ok(
        realHit !== undefined,
        `expected the real (offset=${realOffset}, serial=${realSerial}) in the scan`
      );
      const forged = alternates.filter(
        (a) => !(a.offset === realOffset && a.target === realSerial)
      );
      assert.ok(
        forged.length > 0,
        `expected at least one alternate (offset, target); got ${alternates.length} hits total`
      );
      console.log(
        "  alternate serial witnesses derived from the real fixture:",
        alternates
          .map((a) => `offset=${a.offset} target=${a.target}`)
          .join("; ")
      );
    });

    it("baseline: CertChainRSA256 accepts the honest witness", async function () {
      this.timeout(900_000);
      const witness = await chainCircuit.calculateWitness(chainInput as any);
      await chainCircuit.expectConstraintPass(witness);
    });

    const forgedSerials: { description: string; forgedSerial: bigint }[] = [
      { description: "version INTEGER (value = 2)", forgedSerial: 2n },
      {
        description: "version/serial header overlap (value = 5214)",
        forgedSerial: 5214n,
      },
      { description: "RSA exponent INTEGER (value = 65537)", forgedSerial: 65537n },
    ];

    for (const { description, forgedSerial } of forgedSerials) {
      it(`REJECTS forged serialNumber=${forgedSerial} (${description})`, async function () {
        this.timeout(900_000);
        const live = alternates.find((a) => a.target === forgedSerial);
        assert.ok(
          live !== undefined,
          `forged serial ${forgedSerial} no longer present as an alternate INTEGER in the fixture — update if rotated`
        );
        const attackInput = { ...chainInput, serialNumber: forgedSerial };
        await chainCircuit.expectFail(attackInput as any);
      });
    }
  });

  // Finding 2 (HIGH) — see audit_report_v2.md.
  describe("[HIGH] non-canonical SHA-256 padding is rejected by UserSigRSA256", function () {
    let userSigCircuit: WitnessTester<
      ["tbs", "userPkLimbs", "userRsaSignature", "pkBlind", "challenge"],
      ["pkCommit", "nullifier", "appIdPacked"]
    >;
    let testRsaPrivKey: KeyObject;
    let testRsaPubLimbs: string[];

    function signLimbs(rawMessage: Buffer): string[] {
      const sig = cryptoSign("sha256", rawMessage, {
        key: testRsaPrivKey,
        padding: cryptoConstants.RSA_PKCS1_PADDING,
      });
      return bigIntToChunkedBytes(bytesToBigInt(sig), N_BITS, K_LIMBS_USER);
    }

    function buildWitness(appIdBytes: Uint8Array, tail: Uint8Array) {
      assert.strictEqual(appIdBytes.length, 31, "appIdBytes must be 31 bytes");
      const message = Buffer.concat([appIdBytes, tail]);
      const [padded, paddedLen] = sha256Pad(
        new Uint8Array(message),
        MAX_MESSAGE_LENGTH
      );
      assert.ok(
        paddedLen <= 64,
        `padded length must fit the circuit's 64-byte signed window; got ${paddedLen}`
      );
      return {
        tbs: Array.from(padded).map(String),
        userPkLimbs: testRsaPubLimbs,
        userRsaSignature: signLimbs(message),
        pkBlind: "1",
        challenge: "42",
      };
    }

    before(async function () {
      this.timeout(900_000);
      userSigCircuit = await circomkit.WitnessTester("userSigRS2048", {
        file: "userSig",
        template: "UserSigRSA256",
        params: [MAX_MESSAGE_LENGTH, N_BITS, K_LIMBS_USER],
      });
      const { publicKey, privateKey } = generateKeyPairSync("rsa", {
        modulusLength: USER_MODULUS_BITS,
        publicExponent: 65537,
      });
      testRsaPrivKey = privateKey;
      const jwk = publicKey.export({ format: "jwk" }) as { n: string };
      const modulus = bytesToBigInt(Buffer.from(jwk.n, "base64url"));
      testRsaPubLimbs = bigIntToChunkedBytes(modulus, N_BITS, K_LIMBS_USER);
    });

    it("baseline: canonical 31-byte payload (witness A) is accepted", async function () {
      this.timeout(900_000);
      const appId = Buffer.from("audit-v2-high-test-app-id-fixed", "utf-8");
      const witnessA = buildWitness(appId, Buffer.alloc(0));
      const wA = await userSigCircuit.calculateWitness(witnessA);
      await userSigCircuit.expectConstraintPass(wA);
    });

    it("REJECTS witness with appended tail (tbs[31] != 0x80 — Sybil attack vector)", async function () {
      this.timeout(900_000);
      // Signing (appId ‖ 0x42) puts 0x42 at tbs[31]; the constraint expects 0x80.
      const appId = Buffer.from("audit-v2-high-test-app-id-fixed", "utf-8");
      const witnessB = buildWitness(appId, Buffer.from([0x42]));
      assert.notStrictEqual(
        witnessB.tbs[31],
        "128",
        "expected tbs[31] = 0x42 = '66'; if this fails the fixture changed"
      );
      await userSigCircuit.expectFail(witnessB);
    });
  });

  // Finding 3 (LOW, advisory) — see audit_report_v2.md.
  describe("[LOW] forged tbsModulusTagOffset is rejected by CertChainRSA256", function () {
    it("baseline: real (modulusTagOffset, modulusOffset) extracts the real modulus", async function () {
      this.timeout(900_000);
      const witness = await chainCircuit.calculateWitness(chainInput as any);
      await chainCircuit.expectConstraintPass(witness);
    });

    it("REJECTS forged tbsModulusTagOffset pointing at the RSA exponent INTEGER", async function () {
      this.timeout(900_000);
      // tbs[510] = 0x02 (exponent tag), tbs[511] = 0x03 — fails the 0x82 prefix check.
      const attackInput = { ...chainInput, tbsModulusTagOffset: 510n };
      await chainCircuit.expectFail(attackInput as any);
    });
  });
});
