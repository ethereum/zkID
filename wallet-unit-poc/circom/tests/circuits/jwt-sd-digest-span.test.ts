import { strict as assert } from "assert";
import type { WitnessTester } from "circomkit";
import { sha256 } from "@noble/hashes/sha2";
import { circomkit } from "../common/index.ts";
import { generateMockData } from "../../src/mock-vc-generator.ts";
import { generateJwtInputs } from "../../src/jwt.ts";

const CIRCUIT_PARAMS = [2048, 2000, 4, 50, 128];

const b64url = (s: string) => Buffer.from(s).toString("base64url");
const digest = (disclosure: string) => Buffer.from(sha256(Buffer.from(disclosure))).toString("base64url");

describe("JWT disclosure digest inside _sd (1789509076)", () => {
  let circuit!: WitnessTester<any, any>;

  before(async () => {
    circuit = await circomkit.WitnessTester("JWTSdDigestSpan", {
      file: "jwt",
      template: "JWT",
      params: CIRCUIT_PARAMS,
      recompile: true,
    });
    console.log("#constraints:", await circuit.getConstraintCount());
  });

  it("accepts an ordinary credential", async () => {
    const mock = await generateMockData({ circuitParams: CIRCUIT_PARAMS });
    await circuit.expectConstraintPass(await circuit.calculateWitness(mock.circuitInputs));
  });

  // "sub" is signed before the _sd array, "note" after it closes.
  for (const field of ["sub", "note"] as const) {
    it(`rejects a disclosure whose digest is signed in "${field}", outside _sd`, async () => {
      const fake = b64url(JSON.stringify(["c2FsdHNhbHRzYWx0c2FsdA", "roc_birthday", "0010101"]));
      const fakeDigest = digest(fake);
      const mock = await generateMockData({
        circuitParams: CIRCUIT_PARAMS,
        ...(field === "sub" ? { subject: fakeDigest } : { extraPayload: { note: fakeDigest } }),
      });
      const payload = atob(mock.token.split(".")[1]);
      assert.ok(payload.includes(`"${field}":"${fakeDigest}"`), "fake digest must be signed");
      assert.ok(!mock.hashedClaims.includes(fakeDigest), "fake digest must not be in _sd");

      // Same signed token; slot 0 now carries the fabricated disclosure.
      const attack = generateJwtInputs(
        mock.circuitParams,
        mock.token,
        mock.issuerKey,
        [fakeDigest, mock.hashedClaims[1]],
        [fake, mock.claims[1]],
      );

      let accepted = true;
      try {
        await circuit.calculateWitness(attack);
      } catch (e) {
        if (!/Assert Failed/.test(String(e))) throw e;
        accepted = false;
      }
      assert.equal(accepted, false, "fabricated disclosure was authenticated by a digest outside _sd");
    });
  }

  it("rejects a payload with more than one _sd array", async () => {
    const mock = await generateMockData({
      circuitParams: CIRCUIT_PARAMS,
      extraPayload: { nested: { _sd: [] } },
    });
    await assert.rejects(() => circuit.calculateWitness(mock.circuitInputs), /Assert Failed/);
  });
});
