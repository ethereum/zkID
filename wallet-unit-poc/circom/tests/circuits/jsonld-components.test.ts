import { strict as assert } from "assert";
import type { WitnessTester } from "circomkit";
import { circomkit } from "../common/index.ts";
import { bytesPadded, expectFailIn, JSONLD_BASE, JSONLD_FORMAT } from "../common/jsonld-fixture.ts";
import { normalizeJsonLdValue } from "../../src/jsonld/build-inputs.ts";

const MAX_DOC = 128;
const CS = "<https://www.w3.org/2018/credentials#credentialSubject>";

describe("jsonld NQuadsClaimLine", () => {
  let circuit: WitnessTester<any, any>;

  before(async () => {
    circuit = await circomkit.WitnessTester("nquads_claim_line", {
      file: "components/nquads-claim-line",
      template: "NQuadsClaimLine",
      params: [MAX_DOC, 8, 8, 8],
      recompile: true,
    });
  });

  const line = `<abc> <${JSONLD_BASE}age> "42" .\n`;

  function inputs(doc: string, docEnd: number, pos = 0, enabled = 1) {
    return {
      doc: bytesPadded(doc, MAX_DOC),
      // The Fiat-Shamir challenge only has to be the same on both sides of the check.
      docHash: 1n,
      docEnd: BigInt(docEnd),
      subject: bytesPadded("abc", 8),
      subjectLength: 3n,
      pos: BigInt(pos),
      name: bytesPadded("age", 8),
      nameLength: 3n,
      value: bytesPadded("42", 8),
      valueLength: 2n,
      enabled: BigInt(enabled),
    };
  }

  it("accepts a line that ends exactly at docEnd", async () => {
    await circuit.expectPass(inputs(line, line.length));
  });

  it("rejects docEnd one byte before the end of the line (line feed read from padding)", async () => {
    // The line feed sits at index line.length - 1; as if SHA padding held a 0x0A there.
    await expectFailIn(circuit, inputs(line, line.length - 1), /^NQuadsClaimLine$/, "NQuadsClaimLine");
  });

  it("accepts the same line later in the document, after a line feed", async () => {
    const doc = `<abc> <${JSONLD_BASE}x> "y" .\n` + line;
    await circuit.expectPass({ ...inputs(doc, doc.length), pos: BigInt(doc.length - line.length) });
  });

  it("rejects a position that is not preceded by a line feed", async () => {
    const doc = `z${line}`;
    await expectFailIn(circuit, inputs(doc, doc.length, 1), /^AssertLineStart$/, "NQuadsClaimLine");
  });

  it("rejects a datatype-tagged literal", async () => {
    const doc = `<abc> <${JSONLD_BASE}age> "42"^^<http://www.w3.org/2001/XMLSchema#integer> .\n`;
    await expectFailIn(circuit, inputs(doc, doc.length), /^CheckSubstrInclusionPoly$|^AssertEqualIfTrue$/, "NQuadsClaimLine");
  });

  it("ignores everything for a disabled slot", async () => {
    await circuit.expectPass({
      ...inputs(line, line.length, 0, 0),
      pos: 77n,
      name: bytesPadded("???", 8),
      value: bytesPadded("!!", 8),
    });
  });
});

describe("jsonld NQuadsSubject", () => {
  let circuit: WitnessTester<any, any>;

  before(async () => {
    circuit = await circomkit.WitnessTester("nquads_subject", {
      file: "components/nquads-subject",
      template: "NQuadsSubject",
      params: [MAX_DOC, 8],
      recompile: true,
    });
  });

  const lead = "_:c14n0";
  const line = `${lead} ${CS} <abc> .\n`;

  function inputs(doc: string, docEnd: number) {
    return {
      doc: bytesPadded(doc, MAX_DOC),
      docHash: 1n,
      docEnd: BigInt(docEnd),
      subject: bytesPadded("abc", 8),
      subjectLength: 3n,
      csPos: BigInt(lead.length),
    };
  }

  it("accepts the credentialSubject line", async () => {
    await circuit.expectPass(inputs(line, line.length));
  });

  it("rejects a line that ends after docEnd", async () => {
    await expectFailIn(circuit, inputs(line, line.length - 1), /^NQuadsSubject$/, "NQuadsSubject");
  });

  it("rejects a subject that is a prefix of the IRI (closing '> .' not where it should be)", async () => {
    const doc = `${lead} ${CS} <abcd> .\n`;
    await expectFailIn(circuit, inputs(doc, doc.length), /^CheckSubstrInclusionPoly$|^AssertEqualIfTrue$/, "NQuadsSubject");
  });

  it("rejects an empty subject", async () => {
    const doc = `${lead} ${CS} <> .\n`;
    await expectFailIn(circuit, { ...inputs(doc, doc.length), subject: bytesPadded("", 8), subjectLength: 0n }, /^NQuadsSubject$/, "NQuadsSubject");
  });
});

describe("jsonld JsonLdValueNormalizer", () => {
  let circuit: WitnessTester<any, any>;

  before(async () => {
    circuit = await circomkit.WitnessTester("jsonld_value_normalizer", {
      file: "components/jsonld-value-normalizer",
      template: "JsonLdValueNormalizer",
      params: [64],
      recompile: true,
    });
  });

  const run = (value: string, format: number, enabled = 1) => ({
    value: bytesPadded(value, 64),
    valueLength: BigInt(new TextEncoder().encode(value).length),
    format: BigInt(format),
    enabled: BigInt(enabled),
  });

  const cases: [string, number, string][] = [
    ["bool true", JSONLD_FORMAT.bool, "true"],
    ["uint", JSONLD_FORMAT.uint, "12345"],
    ["iso date", JSONLD_FORMAT.isoDate, "1990-01-01"],
    ["roc date", JSONLD_FORMAT.rocDate, "0790101"],
    ["string", JSONLD_FORMAT.string, "TW"],
    ["digest64 of a long string", JSONLD_FORMAT.digest64, "Ruritanian"],
    ["digest64 of one byte", JSONLD_FORMAT.digest64, "x"],
    ["digest64 of 55 bytes", JSONLD_FORMAT.digest64, "a".repeat(55)],
  ];
  for (const [label, format, value] of cases) {
    it(`matches the TypeScript normalizer: ${label}`, async () => {
      await circuit.expectPass(run(value, format), { normalizedValue: normalizeJsonLdValue(format, value) });
    });
  }

  it("rejects digest64 of 56 bytes (does not fit one SHA-256 block)", async () => {
    await circuit.expectFail(run("a".repeat(56), JSONLD_FORMAT.digest64));
  });

  it("rejects an active slot with format 6", async () => {
    await circuit.expectFail(run("1", 6));
  });

  it("normalizes a disabled slot to 0 whatever it holds", async () => {
    await circuit.expectPass(run("not a date", JSONLD_FORMAT.isoDate, 0), { normalizedValue: 0n });
    await circuit.expectPass(run("Ruritanian", JSONLD_FORMAT.digest64, 0), { normalizedValue: 0n });
  });

  it("keeps the base normalizer's shape checks (iso date of the wrong length)", async () => {
    await circuit.expectFail(run("1990-1-1", JSONLD_FORMAT.isoDate));
  });

  it("digest64 differs between different strings", () => {
    assert.notEqual(
      normalizeJsonLdValue(JSONLD_FORMAT.digest64, "Ruritanian"),
      normalizeJsonLdValue(JSONLD_FORMAT.digest64, "Ruritaniao"),
    );
  });
});
