import { strict as assert } from "assert";
import type { WitnessTester } from "circomkit";
import { circomkit } from "../common/index.ts";
import { buildMdocWitness, MDOC_PARAMS } from "../common/mdoc-fixture.ts";
import { hashClaimName } from "../common/claim-identity.ts";
import { witnessValues } from "../common/witness-signals.ts";
import { createTestMdocCredential } from "../../src/mdoc-fixture.ts";
import { generateMdocCircuitParams, generateMdocInputs, parseMdocClaims } from "../../src/mdoc.ts";

describe("MDOC Circuit", () => {
  let circuit: WitnessTester<any, any>;

  before(async () => {
    circuit = await circomkit.WitnessTester("mdoc", {
      file: "mdoc",
      template: "MDOC",
      params: [...MDOC_PARAMS],
      recompile: true,
    });
    console.log("#constraints:", await circuit.getConstraintCount());
  });

  it("verifies a credential with all 4 claim types", async () => {
    const { inputs } = await buildMdocWitness({
      birth_date: { type: "date" },
      resident_state: { type: "string" },
      family_name: { type: "reveal_digest" },
      given_name: { type: "reveal_digest" },
    });
    const witness = await circuit.calculateWitness(inputs);
    await circuit.expectConstraintPass(witness);
  });

  it("verifies a credential with a subset of claims", async () => {
    const { inputs } = await buildMdocWitness({
      birth_date: { type: "date" },
      resident_state: { type: "string" },
    });
    const witness = await circuit.calculateWitness(inputs);
    await circuit.expectConstraintPass(witness);
  });

  it("rejects a tampered signature", async () => {
    const cred = await createTestMdocCredential();
    const params = generateMdocCircuitParams([...MDOC_PARAMS]);
    const { claims, deviceKeyPos } = parseMdocClaims(cred.tbsData, cred.items, cred.deviceKeyX, {
      birth_date: { type: "date" },
    });

    const tampered = new Uint8Array(cred.signature);
    tampered[0] ^= 0xff;

    assert.throws(
      () => generateMdocInputs(params, cred.tbsData, tampered, cred.issuerPubRaw, claims, deviceKeyPos),
      /Internal ECDSA signature verification failed/,
    );
  });

  describe("claim identity", () => {
    const LONG_NAME = "family_name_national_character";
    const BOUNDARY_NAME = "biometric_template_face";
    const claims = { [LONG_NAME]: "Smithsson", [BOUNDARY_NAME]: "faceblob" };

    it("rejects a name framed by a two-byte CBOR header", async () => {
      const cred = await createTestMdocCredential(claims);
      const params = generateMdocCircuitParams([...MDOC_PARAMS]);
      const parsed = parseMdocClaims(cred.tbsData, cred.items, cred.deviceKeyX, { [LONG_NAME]: { type: "string" } });
      // The generator refuses names over 23 bytes, so the slot is built under an alias.
      parsed.claims[0].identifier = "alias";
      const inputs = generateMdocInputs(
        params,
        cred.tbsData,
        cred.signature,
        cred.issuerPubRaw,
        parsed.claims,
        parsed.deviceKeyPos,
      );

      const truncated = Buffer.concat([Uint8Array.of(0x78, 0x1e), Buffer.from(LONG_NAME).subarray(0, 23)]);
      inputs.identifierCbor[0] = Array.from({ length: MDOC_PARAMS[3] }, (_, i) => BigInt(truncated[i] ?? 0));
      inputs.identifierLengths[0] = 25n;

      await circuit.expectFail(inputs);
    });

    it("hashes a 23-byte name to H(name)", async () => {
      const { inputs } = await buildMdocWitness({ [BOUNDARY_NAME]: { type: "string" } }, claims);
      const witness = await circuit.calculateWitness(inputs);
      await circuit.expectConstraintPass(witness);
      const [hash] = await witnessValues(circuit, witness, ["main.claimIdentifierHashes[0]"]);
      assert.equal(hash, await hashClaimName(BOUNDARY_NAME));
    });

    it("rejects a header that disagrees with the length", async () => {
      const { inputs } = await buildMdocWitness({ birth_date: { type: "date" } });
      const len = Number(inputs.identifierLengths[0]);
      const next = inputs.preimages[0][Number(inputs.identifierPositions[0]) + len];
      inputs.identifierCbor[0][len] = next;
      inputs.identifierLengths[0] = BigInt(len + 1);

      await circuit.expectFail(inputs);
    });

    it("gives an inactive slot identity 0", async () => {
      const { inputs } = await buildMdocWitness({ birth_date: { type: "date" } });
      inputs.identifierCbor[1] = inputs.identifierCbor[1].map((_, i) => BigInt(0x61 + (i % 20)));
      inputs.identifierLengths[1] = 30n;

      const witness = await circuit.calculateWitness(inputs);
      await circuit.expectConstraintPass(witness);
      const [hash] = await witnessValues(circuit, witness, ["main.claimIdentifierHashes[1]"]);
      assert.equal(hash, 0n);
    });
  });

  describe("consistency checks", () => {
    it("rejects a non-boolean claimFlag", async () => {
      const { inputs } = await buildMdocWitness({ birth_date: { type: "date" } });
      const tampered = { ...inputs, claimFlags: [...inputs.claimFlags] };
      tampered.claimFlags[0] = 2n;
      await circuit.expectFail(tampered);
    });

    it("rejects a valueType >= 4", async () => {
      const { inputs } = await buildMdocWitness({ birth_date: { type: "date" } });
      const tampered = { ...inputs, valueTypes: [...inputs.valueTypes] };
      tampered.valueTypes[0] = 4n;
      await circuit.expectFail(tampered);
    });

    it("rejects valueEnd < valueStart (dataLen underflow)", async () => {
      const { inputs } = await buildMdocWitness({ birth_date: { type: "date" } });
      const tampered = {
        ...inputs,
        valueEnds: [...inputs.valueEnds],
        valueStarts: [...inputs.valueStarts],
      };
      tampered.valueEnds[0] = tampered.valueStarts[0] - 1n;
      await circuit.expectFail(tampered);
    });

    it("rejects a dataLen larger than maxValueLen", async () => {
      const { inputs } = await buildMdocWitness({ birth_date: { type: "date" } });
      const params = generateMdocCircuitParams([...MDOC_PARAMS]);
      const tampered = { ...inputs, valueEnds: [...inputs.valueEnds] };
      tampered.valueEnds[0] = tampered.valueStarts[0] + BigInt(params.maxValueLen + 1);
      await circuit.expectFail(tampered);
    });
  });
});
