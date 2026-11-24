import { strict as assert } from "assert";
import type { WitnessTester } from "circomkit";
import { circomkit } from "../common/index.ts";
import { witnessValues } from "../common/witness-signals.ts";
import {
  BOTH_CLAIMS,
  buildFixture,
  bytesPadded,
  expectFailIn,
  issuer,
  JSONLD_FORMAT,
  offsetOf,
  otherIssuerKey,
  PROD_PARAMS,
  withDoc,
} from "../common/jsonld-fixture.ts";

describe("jsonld circuit", () => {
  let circuit: WitnessTester<any, any>;

  before(async () => {
    circuit = await circomkit.WitnessTester("jsonld", {
      file: "jsonld",
      template: "JSONLD",
      params: [...PROD_PARAMS],
      recompile: true,
    });
    console.log("#constraints:", await circuit.getConstraintCount());
  });

  describe("positive", () => {
    it("accepts the fixture with both claims and exposes the shared signals", async () => {
      const { inputs, meta } = buildFixture();
      const witness = await circuit.calculateWitness(inputs);
      await circuit.expectConstraintPass(witness);

      const [vx, v1, dx, dy, h0, h1] = await witnessValues(circuit, witness, [
        "main.normalizedClaimValues[0]",
        "main.normalizedClaimValues[1]",
        "main.deviceKeyX",
        "main.deviceKeyY",
        "main.claimIdentifierHashes[0]",
        "main.claimIdentifierHashes[1]",
      ]);
      assert.equal(vx, 19900101n);
      assert.equal(v1, meta.normalizedClaimValues[1]);
      assert.equal(dx, meta.deviceKey.x);
      assert.equal(dy, meta.deviceKey.y);
      assert.equal(h0, meta.claimIdentifierHashes[0]);
      assert.equal(h1, meta.claimIdentifierHashes[1]);
    });

    it("accepts a disabled slot and outputs zeros for it", async () => {
      const { inputs } = buildFixture([BOTH_CLAIMS[0]]);
      const witness = await circuit.calculateWitness(inputs);
      await circuit.expectConstraintPass(witness);
      const [v1, h1] = await witnessValues(circuit, witness, [
        "main.normalizedClaimValues[1]",
        "main.claimIdentifierHashes[1]",
      ]);
      assert.equal(v1, 0n);
      assert.equal(h1, 0n);
    });

    it("ignores the position and format of a disabled slot", async () => {
      const { inputs } = buildFixture([BOTH_CLAIMS[0]]);
      const tampered = { ...inputs, linePos: [inputs.linePos[0], 999n], claimFormats: [inputs.claimFormats[0], 3n] };
      const witness = await circuit.calculateWitness(tampered);
      await circuit.expectConstraintPass(witness);
    });

    it("accepts a claim on the last line of the document (line ends at the true length)", async () => {
      const base = buildFixture();
      const doc = base.nquads + `<${base.meta.subject}> <https://example.org/eid#zzz> "last" .\n`;
      const { inputs, meta } = buildFixture([{ name: "zzz", format: JSONLD_FORMAT.string }], undefined, doc);
      const witness = await circuit.calculateWitness(inputs);
      await circuit.expectConstraintPass(witness);
      const [v0] = await witnessValues(circuit, witness, ["main.normalizedClaimValues[0]"]);
      assert.equal(v0, meta.normalizedClaimValues[0]);
    });

    it("accepts a claim on the first line of the document (position 0)", async () => {
      const { inputs, meta } = buildFixture([{ name: "addressCountry", format: JSONLD_FORMAT.string }]);
      assert.equal(inputs.linePos[0], 0n);
      const witness = await circuit.calculateWitness(inputs);
      await circuit.expectConstraintPass(witness);
      const [v0] = await witnessValues(circuit, witness, ["main.normalizedClaimValues[0]"]);
      assert.equal(v0, meta.normalizedClaimValues[0]);
    });
  });

  describe("claim line aiming", () => {
    it("rejects linePos re-aimed at another claim's line", async () => {
      const { nquads, inputs, meta } = buildFixture();
      const other = BigInt(offsetOf(nquads, `<${meta.subject}> <https://example.org/eid#name>`));
      await expectFailIn(circuit, { ...inputs, linePos: [other, inputs.linePos[1]] }, /^CheckSubstrInclusionPoly$|^AssertEqualIfTrue$/);
    });

    it("rejects linePos pointing into the middle of a line", async () => {
      const { inputs } = buildFixture();
      await circuit.expectFail({ ...inputs, linePos: [inputs.linePos[0] + 1n, inputs.linePos[1]] });
    });

    it("rejects a line that only matches after a non-line-feed byte (fake line inside a literal)", async () => {
      const base = buildFixture();
      const subject = base.meta.subject;
      const fake = `<${subject}> <https://example.org/eid#dateOfBirth> "1980-01-01`;
      // The name literal now ends with text that, from its first '<', is a complete
      // dateOfBirth line including the closing quote, space, dot and line feed.
      const doc = base.nquads.replace('"Sample Holder"', `"x ${fake}"`);
      assert.notEqual(doc, base.nquads);
      const forged = withDoc(base.inputs, doc, base.proofHash);
      const fakePos = BigInt(offsetOf(doc, fake));
      const fakeInputs = {
        ...forged,
        linePos: [fakePos, forged.linePos[1]],
        values: [bytesPadded("1980-01-01", 64), forged.values[1]],
      };

      // Control: the same forged document with the honest line aimed is accepted, so
      // the only thing wrong with the fake is where it starts.
      const control = await circuit.calculateWitness(forged);
      await circuit.expectConstraintPass(control);
      await expectFailIn(circuit, fakeInputs, /^AssertLineStart$/);
    });

    it("rejects a name that differs from the line's name", async () => {
      const { inputs } = buildFixture();
      const names = inputs.names.map((n) => [...n]);
      names[0][10] = names[0][10] + 1n;
      await circuit.expectFail({ ...inputs, names });
    });

    it("rejects a value that differs from the line's value", async () => {
      const { inputs } = buildFixture();
      const values = inputs.values.map((v) => [...v]);
      values[0][3] = values[0][3] + 1n;
      await circuit.expectFail({ ...inputs, values });
    });

    it("rejects a nameLength one short", async () => {
      const { inputs } = buildFixture();
      await circuit.expectFail({ ...inputs, nameLengths: [inputs.nameLengths[0] - 1n, inputs.nameLengths[1]] });
    });
  });

  describe("value alphabet", () => {
    it("rejects a value that contains an escaped quote", async () => {
      const base = buildFixture([
        { name: "dateOfBirth", format: JSONLD_FORMAT.isoDate },
        { name: "name", format: JSONLD_FORMAT.bool },
      ]);
      const raw = 'Sample \\"Holder';
      const doc = base.nquads.replace("Sample Holder", raw);
      const forged = withDoc(base.inputs, doc, base.proofHash);
      const inputs = {
        ...forged,
        values: [forged.values[0], bytesPadded(raw, 64)],
        valueLengths: [forged.valueLengths[0], BigInt(raw.length)],
      };
      await expectFailIn(circuit, inputs, /^NQuadsClaimLine$/);
    });

    it("rejects a name outside [A-Za-z0-9_]", async () => {
      const base = buildFixture();
      const doc = base.nquads.replace("#dateOfBirth>", "#date-fBirth>");
      const names = base.inputs.names.map((n) => [...n]);
      names[0] = bytesPadded("date-fBirth", 31);
      const forged = withDoc({ ...base.inputs, names }, doc, base.proofHash);
      await expectFailIn(circuit, forged, /^NQuadsClaimLine$/);
    });
  });

  describe("subject", () => {
    it("rejects a subject one byte short", async () => {
      const { inputs } = buildFixture();
      const subject = [...inputs.subject];
      subject[Number(inputs.subjectLength) - 1] = 0n;
      await circuit.expectFail({ ...inputs, subject, subjectLength: inputs.subjectLength - 1n });
    });

    it("rejects a subject containing '>'", async () => {
      const base = buildFixture();
      const s = base.meta.subject;
      const bad = s.slice(0, 20) + ">" + s.slice(21);
      const doc = base.nquads.replaceAll(s, bad);
      const forged = withDoc({ ...base.inputs, subject: bytesPadded(bad, 128) }, doc, base.proofHash, { subject: bad });
      await expectFailIn(circuit, forged, /^NQuadsSubject$/);
    });

    it("rejects csPos aimed at a different position", async () => {
      const { inputs } = buildFixture();
      await circuit.expectFail({ ...inputs, csPos: inputs.csPos - 1n });
    });
  });

  describe("signature and hashes", () => {
    it("rejects a flipped document byte", async () => {
      const { inputs, nquads } = buildFixture();
      const doc = [...inputs.doc];
      const i = offsetOf(nquads, '"ZZ"') + 1;
      doc[i] = doc[i] ^ 1n;
      await circuit.expectFail({ ...inputs, doc });
    });

    it("rejects a wrong proofHash", async () => {
      const { inputs } = buildFixture();
      const proofHash = [...inputs.proofHash];
      proofHash[0] = proofHash[0] ^ 1n;
      await circuit.expectFail({ ...inputs, proofHash });
    });

    it("rejects a wrong issuer key", async () => {
      const { inputs } = buildFixture();
      const k = otherIssuerKey();
      await circuit.expectFail({ ...inputs, pubKeyX: k.x, pubKeyY: k.y });
      assert.notEqual(k.x, issuer.x);
    });

    it("rejects a tampered signature", async () => {
      const { inputs } = buildFixture();
      await circuit.expectFail({ ...inputs, sig_r: inputs.sig_r + 1n });
    });

    it("rejects a docLength other than the padded length", async () => {
      const { inputs } = buildFixture();
      await circuit.expectFail({ ...inputs, docLength: inputs.docLength + 64n });
      await circuit.expectFail({ ...inputs, docLength: inputs.docLength - 64n });
    });
  });

  describe("consistency", () => {
    it("rejects a non-boolean claimFlag", async () => {
      const { inputs } = buildFixture();
      await circuit.expectFail({ ...inputs, claimFlags: [inputs.claimFlags[0], 2n] });
    });

    it("rejects an active slot with an unknown format", async () => {
      const { inputs } = buildFixture();
      await circuit.expectFail({ ...inputs, claimFormats: [6n, inputs.claimFormats[1]] });
    });

    it("rejects an iso_date value of the wrong shape", async () => {
      const { inputs } = buildFixture();
      // nationality ("Ruritanian") read as a date
      await circuit.expectFail({ ...inputs, claimFormats: [inputs.claimFormats[0], BigInt(JSONLD_FORMAT.isoDate)] });
    });
  });

  describe("device key", () => {
    it("rejects a deviceKey value with a non-base64url character", async () => {
      const base = buildFixture();
      const dk = String.fromCharCode(...base.inputs.deviceKeyValue.slice(0, Number(base.inputs.deviceKeyValueLength)).map(Number));
      const bad = dk.slice(0, 10) + "+" + dk.slice(11);
      const doc = base.nquads.replace(dk, bad);
      const forged = withDoc({ ...base.inputs, deviceKeyValue: bytesPadded(bad, 252) }, doc, base.proofHash);
      await expectFailIn(circuit, forged, /^JsonLdDeviceKey$/);
    });

    it("rejects deviceKeyLinePos aimed at another claim's line", async () => {
      const { inputs } = buildFixture();
      await circuit.expectFail({ ...inputs, deviceKeyLinePos: inputs.linePos[0] });
    });

    it("rejects jwkXPos aimed at the y anchor", async () => {
      const { inputs } = buildFixture();
      await circuit.expectFail({ ...inputs, jwkXPos: inputs.jwkYPos });
    });

    it("rejects jwkXPos shifted by one", async () => {
      const { inputs } = buildFixture();
      await circuit.expectFail({ ...inputs, jwkXPos: inputs.jwkXPos + 1n });
    });

    it("rejects swapped x and y anchors", async () => {
      const { inputs } = buildFixture();
      await circuit.expectFail({ ...inputs, jwkXPos: inputs.jwkYPos, jwkYPos: inputs.jwkXPos });
    });
  });
});
