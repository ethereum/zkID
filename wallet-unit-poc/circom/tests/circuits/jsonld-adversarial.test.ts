import { strict as assert } from "assert";
import type { WitnessTester } from "circomkit";
import { p256 } from "@noble/curves/p256";
import { Field } from "@noble/curves/abstract/modular";
import { sha256 } from "@noble/hashes/sha2";
import { circomkit } from "../common/index.ts";
import { witnessValues } from "../common/witness-signals.ts";
import {
  buildFixture,
  bytesPadded,
  expectFailIn,
  JSONLD_BASE as B,
  JSONLD_FORMAT,
  offsetOf,
  PROD_PARAMS,
  withDoc,
  type JsonLdInputs,
} from "../common/jsonld-fixture.ts";
import { signJsonLd } from "../../src/jsonld/test-fixture.ts";

// Adversarial soundness tests for circuits/jsonld.circom.
//
// Model: the attacker holds a document the issuer really signed, so structural attacks
// re-sign a forged document with the test issuer key (withDoc) and only the structure is
// under test. Signature attacks use a different key. Every attack test pairs the attack with
// a control built from the same setup, so a rejection is attributable to the attack.
//
// Names: "ATTACK" tests must be rejected. "RESIDUAL" tests are documented limits of the
// circuit (properties of the signed document, not of the witness) and are expected to pass.

const FIELD = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"); // secq256r1 scalar field
const P256_P = BigInt("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
const Fn = Field(FIELD);
const UTF8 = new TextEncoder();
const CS = "https://www.w3.org/2018/credentials#credentialSubject";
const MAX_DOC = PROD_PARAMS[0];

const b64c = (n: bigint): string => {
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--, n >>= 8n) out[i] = Number(n & 0xffn);
  return Buffer.from(out).toString("base64url");
};
const dec = (arr: bigint[], len: bigint): string => String.fromCharCode(...arr.slice(0, Number(len)).map(Number));

describe("jsonld-adversarial", () => {
  let circuit: WitnessTester<any, any>;
  let base: ReturnType<typeof buildFixture>;
  let S: string; // honest credentialSubject IRI
  let OTHER: string; // same length, different IRI
  let DK_B64: string; // honest deviceKey literal
  let KEY: { x: bigint; y: bigint };

  before(async () => {
    circuit = await circomkit.WitnessTester("jsonld_adversarial", {
      file: "jsonld",
      template: "JSONLD",
      params: [...PROD_PARAMS],
      recompile: true,
    });
    base = buildFixture();
    S = base.meta.subject;
    OTHER = S.slice(0, -4) + "ZZZZ";
    DK_B64 = dec(base.inputs.deviceKeyValue, base.inputs.deviceKeyValueLength);
    KEY = base.meta.deviceKey;
  });

  // ---- helpers ---------------------------------------------------------------------------

  // value0, value1, hash0, hash1, devX, devY of a witness
  const out = (w: bigint[]) =>
    witnessValues(circuit, w, [
      "main.normalizedClaimValues[0]",
      "main.normalizedClaimValues[1]",
      "main.claimIdentifierHashes[0]",
      "main.claimIdentifierHashes[1]",
      "main.deviceKeyX",
      "main.deviceKeyY",
    ]);

  async function accept(inputs: unknown): Promise<bigint[]> {
    const w = await circuit.calculateWitness(inputs as any);
    await circuit.expectConstraintPass(w);
    return w;
  }

  /** Witness generation must throw, or the constraint system must be unsatisfied. */
  async function reject(inputs: unknown, template?: RegExp): Promise<void> {
    if (template) return expectFailIn(circuit, inputs, template);
    let w: bigint[];
    try {
      w = await circuit.calculateWitness(inputs as any);
    } catch (e) {
      // A malformed test input must not pass as a rejection: only a circuit failure counts.
      assert.match(String(e), /Assert Failed|Error in template/, `not a circuit failure: ${e}`);
      return;
    }
    try {
      await circuit.expectConstraintPass(w);
    } catch {
      return;
    }
    assert.fail("ATTACK SUCCEEDED: witness generated and every constraint satisfied");
  }

  const lineAt = (nq: string, subj: string, name: string) => BigInt(offsetOf(nq, `<${subj}> <${B}${name}> `));

  /** Re-sign `nq` and re-locate the honest lines; `edit` patches the result. */
  function forge(nq: string, edit: Partial<JsonLdInputs> = {}, inputs: JsonLdInputs = base.inputs): JsonLdInputs {
    return { ...withDoc(inputs, nq, base.proofHash), ...edit };
  }

  function setSlot(
    inputs: JsonLdInputs,
    i: number,
    s: { name?: string; value?: string; format?: number; linePos?: bigint; flag?: bigint },
  ): JsonLdInputs {
    const next = {
      ...inputs,
      linePos: [...inputs.linePos],
      names: inputs.names.map((n) => [...n]),
      nameLengths: [...inputs.nameLengths],
      values: inputs.values.map((v) => [...v]),
      valueLengths: [...inputs.valueLengths],
      claimFormats: [...inputs.claimFormats],
      claimFlags: [...inputs.claimFlags],
    };
    if (s.name !== undefined) {
      next.names[i] = bytesPadded(s.name, 31);
      next.nameLengths[i] = BigInt(UTF8.encode(s.name).length);
    }
    if (s.value !== undefined) {
      next.values[i] = bytesPadded(s.value, 64);
      next.valueLengths[i] = BigInt(UTF8.encode(s.value).length);
    }
    if (s.format !== undefined) next.claimFormats[i] = BigInt(s.format);
    if (s.linePos !== undefined) next.linePos[i] = s.linePos;
    if (s.flag !== undefined) next.claimFlags[i] = s.flag;
    return next;
  }

  const tripleLine = (subj: string, pred: string, val: string) => `<${subj}> <${pred}> "${val}" .\n`;

  /** Swap the deviceKey literal for a JWK built from `json`; anchors are the first occurrences. */
  function withDeviceKey(json: string, anchors: { x?: number; y?: number } = {}, nq = base.nquads, extra: Partial<JsonLdInputs> = {}) {
    const b64 = Buffer.from(json, "latin1").toString("base64url");
    assert.ok(b64.length <= 252, "test JWK too long");
    const doc = nq.replace(DK_B64, b64);
    return forge(doc, {
      deviceKeyValue: bytesPadded(b64, 252),
      deviceKeyValueLength: BigInt(b64.length),
      jwkXPos: BigInt(anchors.x ?? json.indexOf('"x":"')),
      jwkYPos: BigInt(anchors.y ?? json.indexOf('"y":"')),
      ...extra,
    });
  }
  const jwkJson = (x: string, y: string) => `{"kty":"EC","crv":"P-256","x":"${x}","y":"${y}"}`;

  // ---- 0. sanity -------------------------------------------------------------------------

  it("control: the honest fixture is accepted and exposes the expected outputs", async () => {
    const w = await accept(base.inputs);
    const o = await out(w);
    assert.equal(o[0], base.meta.normalizedClaimValues[0]);
    assert.equal(o[1], base.meta.normalizedClaimValues[1]);
    assert.equal(o[2], base.meta.claimIdentifierHashes[0]);
    assert.equal(o[3], base.meta.claimIdentifierHashes[1]);
    assert.equal(o[4], KEY.x);
    assert.equal(o[5], KEY.y);
  });

  // ---- 1. line-boundary bypass -----------------------------------------------------------

  describe("line boundary", () => {
    it("ATTACK: linePos 0 when the first line is not a claim line", async () => {
      const first = `_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <${B}Extra> .\n`;
      const honest = forge(first + base.nquads);
      await accept(honest); // control
      await reject({ ...honest, linePos: [0n, honest.linePos[1]] });
      await reject({ ...honest, deviceKeyLinePos: 0n });
      await reject({ ...honest, csPos: 0n });
    });

    it("ATTACK: claim line glued after another triple on the same physical line", async () => {
      const junk = `_:c14n0 <http://example.org/p> <http://example.org/o> .`;
      const dobLine = `<${S}> <${B}dateOfBirth> `;
      const control = forge(base.nquads.replace(dobLine, junk + "\n" + dobLine));
      await accept(control);
      const glued = forge(base.nquads.replace(dobLine, junk + " " + dobLine));
      await reject(glued, /^AssertLineStart$/);
    });

    it("ATTACK: line following a CR (not an LF) is not a line start", async () => {
      const dobLine = `<${S}> <${B}dateOfBirth> `;
      const control = forge(base.nquads.replace(dobLine, "\n" + dobLine));
      await accept(control);
      const cr = forge(base.nquads.replace(dobLine, "\r" + dobLine));
      await reject(cr, /^AssertLineStart$/);
    });

    it("ATTACK: a fake deviceKey line inside another literal supplies an attacker key", async () => {
      const att = p256.getPublicKey(p256.utils.randomPrivateKey(), false);
      const big = (b: Uint8Array) => b.reduce((n, v) => (n << 8n) | BigInt(v), 0n);
      const ax = big(att.slice(1, 33));
      const ay = big(att.slice(33, 65));
      const attJson = jwkJson(b64c(ax), b64c(ay));
      const attB64 = Buffer.from(attJson).toString("base64url");
      const fake = `<${S}> <${B}deviceKey> "${attB64}`;
      const doc = base.nquads.replace('"Sample Holder"', `"x ${fake}"`);
      assert.notEqual(doc, base.nquads);
      const honest = forge(doc); // control: honest deviceKey line aimed
      await accept(honest);
      const attack = {
        ...honest,
        deviceKeyLinePos: BigInt(offsetOf(doc, fake)),
        deviceKeyValue: bytesPadded(attB64, 252),
        deviceKeyValueLength: BigInt(attB64.length),
        jwkXPos: BigInt(attJson.indexOf('"x":"')),
        jwkYPos: BigInt(attJson.indexOf('"y":"')),
      };
      await reject(attack, /^AssertLineStart$/);
    });

    it("RESIDUAL (expected to pass): a raw LF inside a literal makes a fake claim line a real line boundary", async () => {
      // Canonical N-Quads (RDFC-1.0) escapes LF as \n, so an honest issuer cannot sign this
      // document. A non-canonical signed document defeats the line-boundary rule.
      const fake = `<${S}> <${B}dateOfBirth> "1980-01-01`;
      const doc = base.nquads.replace('"Sample Holder"', `"x\n${fake}"`);
      const honest = forge(doc);
      await accept(honest);
      const w = await accept({
        ...honest,
        linePos: [BigInt(offsetOf(doc, fake)), honest.linePos[1]],
        values: [bytesPadded("1980-01-01", 64), honest.values[1]],
      });
      assert.equal((await out(w))[0], 19800101n);
    });
  });

  // ---- 2. subject confusion --------------------------------------------------------------

  describe("subject confusion", () => {
    const otherDob = () => tripleLine(OTHER, B + "dateOfBirth", "1970-01-01");

    it("ATTACK: a claim from another subject's line while the subject is the credentialSubject", async () => {
      const doc = otherDob() + base.nquads;
      const honest = forge(doc);
      await accept(honest);
      await reject({
        ...honest,
        linePos: [lineAt(doc, OTHER, "dateOfBirth"), honest.linePos[1]],
        values: [bytesPadded("1970-01-01", 64), honest.values[1]],
      });
    });

    it("ATTACK: swapping in the other subject without moving csPos", async () => {
      const doc = otherDob() + base.nquads;
      const honest = forge(doc);
      await accept(honest);
      await reject({
        ...honest,
        subject: bytesPadded(OTHER, 128),
        linePos: [lineAt(doc, OTHER, "dateOfBirth"), honest.linePos[1]],
        values: [bytesPadded("1970-01-01", 64), honest.values[1]],
      });
    });

    it("ATTACK: the deviceKey line belongs to another subject", async () => {
      const otherKey = Buffer.from(jwkJson(b64c(5n), b64c(6n))).toString("base64url");
      const doc = tripleLine(OTHER, B + "deviceKey", otherKey) + base.nquads;
      const honest = forge(doc);
      await accept(honest);
      await reject({
        ...honest,
        deviceKeyLinePos: lineAt(doc, OTHER, "deviceKey"),
        deviceKeyValue: bytesPadded(otherKey, 252),
        deviceKeyValueLength: BigInt(otherKey.length),
        jwkXPos: BigInt(jwkJson(b64c(5n), b64c(6n)).indexOf('"x":"')),
        jwkYPos: BigInt(jwkJson(b64c(5n), b64c(6n)).indexOf('"y":"')),
      });
    });

    it("ATTACK: claims are not a subject's when the claim line's subject is an extension of the IRI", async () => {
      // `<S2>` where S2 = S + "x": the pinned `>` right after the subject breaks the match.
      const doc = tripleLine(S + "x", B + "dateOfBirth", "1970-01-01") + base.nquads;
      const honest = forge(doc);
      await accept(honest);
      await reject({
        ...honest,
        linePos: [lineAt(doc, S + "x", "dateOfBirth"), honest.linePos[1]],
        values: [bytesPadded("1970-01-01", 64), honest.values[1]],
      });
    });

    it("RESIDUAL (expected to pass): a signed document with two credentialSubject lines lets the prover choose", async () => {
      // Precondition of the circuit: exactly one credentialSubject line. The pinned CS
      // predicate may sit under any subject node, so a document that really carries a
      // second credential (or a second subject) lets the prover pick which one to prove.
      const second = `<urn:uuid:other-credential> <${CS}> <${OTHER}> .\n`;
      // S's unused lines are dropped to stay inside maxDocLen.
      const kept = base.nquads.split("\n").filter((l) => !/#(name|gender|documentNumber|documentType|credentialId|addressCountry)>/.test(l)).join("\n");
      const doc = second + tripleLine(OTHER, B + "dateOfBirth", "1970-01-01") + tripleLine(OTHER, B + "nationality", "Other") +
        tripleLine(OTHER, B + "deviceKey", DK_B64) + kept;
      const asOther = forge(doc, {
        subject: bytesPadded(OTHER, 128),
        csPos: BigInt(offsetOf(doc, ` <${CS}> <${OTHER}>`)),
        linePos: [lineAt(doc, OTHER, "dateOfBirth"), lineAt(doc, OTHER, "nationality")],
        deviceKeyLinePos: lineAt(doc, OTHER, "deviceKey"),
        values: [bytesPadded("1970-01-01", 64), bytesPadded("Other", 64)],
        valueLengths: [10n, 5n],
      });
      const w = await accept(asOther);
      assert.equal((await out(w))[0], 19700101n);
    });
  });

  // ---- 3. prefix and IRI collisions ------------------------------------------------------

  describe("name and IRI collisions", () => {
    it("ATTACK: a name that is a prefix of the real predicate", async () => {
      await accept(base.inputs); // control
      await reject(setSlot(base.inputs, 0, { name: "dateOf" }));
      await reject(setSlot(base.inputs, 0, { name: "d" }));
    });

    it("ATTACK: a name that extends the real predicate", async () => {
      await reject(setSlot(base.inputs, 0, { name: "dateOfBirthX" }));
    });

    it("ATTACK: a line whose predicate is the requested name plus a suffix", async () => {
      const doc = tripleLine(S, B + "dateOfBirthX", "2000-02-02") + base.nquads;
      const honest = forge(doc);
      await accept(honest);
      await reject({
        ...honest,
        linePos: [lineAt(doc, S, "dateOfBirthX"), honest.linePos[1]],
        values: [bytesPadded("2000-02-02", 64), honest.values[1]],
      });
    });

    for (const variant of [
      `https://example.org/eid2#dateOfBirth`,
      `http://example.org/eid#dateOfBirth`,
      `https://example.org/eid#sub/dateOfBirth`,
      `https://example.com/eid#dateOfBirth`,
      `https://example.org/eid#/dateOfBirth`,
      `https://example.org/EID#dateOfBirth`,
    ]) {
      it(`ATTACK: predicate IRI ${variant} is not the eid namespace`, async () => {
        const fakeLine = tripleLine(S, variant, "2000-02-02");
        const doc = fakeLine + base.nquads;
        const honest = forge(doc);
        await accept(honest);
        await reject({
          ...honest,
          linePos: [BigInt(offsetOf(doc, `<${S}> <${variant}> `)), honest.linePos[1]],
          values: [bytesPadded("2000-02-02", 64), honest.values[1]],
        });
      });
    }
  });

  // ---- 4. value truncation and extension -------------------------------------------------

  describe("value extent", () => {
    // slot 1 is nationality = "Ruritanian" (10 bytes), format digest64
    it("ATTACK: value truncated to a prefix, bytes cleared", async () => {
      await accept(base.inputs);
      await reject(setSlot(base.inputs, 1, { value: "Ruritania" }));
      await reject(setSlot(base.inputs, 1, { value: "Rurit" }));
      await reject(setSlot(base.inputs, 1, { value: "B" }));
    });

    it("ATTACK: valueLength shorter than the value while the bytes stay (stale tail)", async () => {
      const inputs = { ...base.inputs, valueLengths: [base.inputs.valueLengths[0], base.inputs.valueLengths[1] - 1n] };
      await reject(inputs);
    });

    it("ATTACK: valueLength longer than the value", async () => {
      const real = base.inputs.valueLengths[1];
      await reject({ ...base.inputs, valueLengths: [base.inputs.valueLengths[0], real + 1n] });
      await reject({ ...base.inputs, valueLengths: [base.inputs.valueLengths[0], real + 4n] });
      // extended with the closing quote itself
      await reject(setSlot(base.inputs, 1, { value: 'Ruritanian"' }));
      // extended with the literal's tail, quote included
      await reject(setSlot(base.inputs, 1, { value: 'Ruritanian" .' }));
      // extended with a space where the quote is
      await reject(setSlot(base.inputs, 1, { value: "Ruritanian " }));
    });

    it("ATTACK: value that ends at the backslash of an escaped quote", async () => {
      const doc = base.nquads.replace('"Sample Holder"', '"Say \\"hi\\" ok"');
      const honest = forge(doc);
      await accept(honest);
      const attack = setSlot(honest, 1, { name: "name", value: "Say \\", format: JSONLD_FORMAT.string, linePos: lineAt(doc, S, "name") });
      await reject(attack);
    });

    it("ATTACK: backslash is rejected even when the literal's bytes match (unterminated-escape line)", async () => {
      // Line `... "a\" .\n`: a parser reads the literal as `a" .`, the circuit would otherwise
      // read `a\`. Only the value alphabet can reject it.
      const doc = base.nquads.replace('<' + S + '> <' + B + 'name> "Sample Holder" .\n', `<${S}> <${B}name> "a\\" .\n`);
      assert.ok(doc.includes('"a\\" .\n'));
      const honest = forge(doc);
      await accept(honest);
      const attack = setSlot(honest, 1, { name: "name", value: "a\\", format: JSONLD_FORMAT.string, linePos: lineAt(doc, S, "name") });
      await reject(attack, /^NQuadsClaimLine$/);
    });

    for (const [label, ch] of [
      ["quote", '"'],
      ["backslash", "\\"],
      ["line feed", "\n"],
      ["carriage return", "\r"],
    ] as const) {
      it(`ATTACK: a raw ${label} inside the claimed value is rejected though the bytes match`, async () => {
        const literal = `a${ch}b`;
        const doc = base.nquads.replace('"Sample Holder"', `"${literal}"`);
        const honest = forge(doc);
        await accept(honest); // control: the same document with the honest slots
        const attack = setSlot(honest, 1, { name: "name", value: literal, format: JSONLD_FORMAT.string, linePos: lineAt(doc, S, "name") });
        await reject(attack, /^NQuadsClaimLine$/);
      });
    }

    it("ATTACK: valueLength 0, over maxValueLen and wrapped lengths on an enabled slot", async () => {
      await reject({ ...base.inputs, valueLengths: [base.inputs.valueLengths[0], 0n] });
      await reject({ ...base.inputs, valueLengths: [base.inputs.valueLengths[0], 65n] });
      await reject({ ...base.inputs, valueLengths: [base.inputs.valueLengths[0], FIELD - 1n] });
      await reject({ ...base.inputs, valueLengths: [base.inputs.valueLengths[0], FIELD - 55n] });
      await reject({ ...base.inputs, valueLengths: [base.inputs.valueLengths[0], 256n + 9n] });
    });

    it("ATTACK: nameLength 0, over maxNameLen and wrapped lengths on an enabled slot", async () => {
      const nl = (v: bigint) => ({ ...base.inputs, nameLengths: [v, base.inputs.nameLengths[1]] });
      await reject(nl(0n));
      await reject(nl(32n));
      await reject(nl(FIELD - 1n));
      await reject(nl(FIELD - 11n));
      await reject(nl(64n + 11n));
    });
  });

  // ---- 5. padding region and document length ---------------------------------------------

  describe("padding and document length", () => {
    it("ATTACK: last line without a trailing LF (the line feed would be read from SHA padding)", async () => {
      const claimed = buildFixture(
        [{ name: "zzz", format: JSONLD_FORMAT.string }],
        undefined,
        base.nquads + tripleLine(S, B + "zzz", "last"),
      );
      await accept(claimed.inputs); // control: with the LF
      const noLf = (claimed.nquads).slice(0, -1);
      const forged = withDoc(claimed.inputs, noLf, claimed.proofHash);
      await reject(forged);
    });

    it("ATTACK: positions inside the SHA padding", async () => {
      const len = base.inputs.docLength;
      for (const pos of [len - 1n, len - 8n, len - 64n + 8n, len - 2n]) {
        await reject({ ...base.inputs, linePos: [pos, base.inputs.linePos[1]] });
        await reject({ ...base.inputs, csPos: pos });
        await reject({ ...base.inputs, deviceKeyLinePos: pos });
      }
    });

    it("ATTACK: docLength that is not the padded length", async () => {
      const len = base.inputs.docLength;
      for (const bad of [0n, 1n, 64n, len - 1n, len + 1n, len - 64n, len + 64n, BigInt(MAX_DOC), BigInt(MAX_DOC) + 1n, FIELD - 1n, FIELD - len]) {
        await reject({ ...base.inputs, docLength: bad });
      }
    });

    it("ATTACK: truncated docLength with the dropped block zeroed (shorter document must not hash)", async () => {
      const len = Number(base.inputs.docLength);
      const doc = base.inputs.doc.map((b, i) => (i >= len - 64 ? 0n : b));
      await reject({ ...base.inputs, doc, docLength: BigInt(len - 64) });
    });

    it("ATTACK: non-zero bytes after docLength", async () => {
      const doc = [...base.inputs.doc];
      doc[Number(base.inputs.docLength) + 5] = 1n;
      await reject({ ...base.inputs, doc });
    });

    it("ATTACK: document bytes outside 0..255 (aliasing a byte through the field)", async () => {
      const i = offsetOf(base.nquads, "dateOfBirth");
      for (const delta of [256n, FIELD - 256n, 1n << 64n]) {
        const doc = [...base.inputs.doc];
        doc[i] = (doc[i] + delta) % FIELD;
        await reject({ ...base.inputs, doc });
      }
    });

    it("ATTACK: forged length trailer in the padding", async () => {
      const doc = [...base.inputs.doc];
      const end = Number(base.inputs.docLength);
      doc[end - 1] = doc[end - 1] - 8n; // claims a document 1 byte shorter
      await reject({ ...base.inputs, doc });
    });
  });

  // ---- 6. field-overflow tricks ----------------------------------------------------------

  describe("field overflow", () => {
    const flags = (a: bigint, b: bigint) => ({ ...base.inputs, claimFlags: [a, b] });
    const INV2 = Fn.inv(2n);

    it("ATTACK: non-boolean claimFlags (2, p-1, 1/2, wrap values) on an active or disabled slot", async () => {
      for (const bad of [2n, 3n, FIELD - 1n, INV2, FIELD - 2n, 1n << 128n]) {
        await reject(flags(bad, 1n));
        await reject(flags(1n, bad));
        await reject(flags(0n, bad));
        await reject(flags(bad, 0n));
      }
    });

    it("ATTACK: out-of-range claimFormats on an enabled slot", async () => {
      for (const bad of [6n, 7n, 255n, 256n, FIELD - 1n, 1n << 64n, FIELD - 5n]) {
        await reject({ ...base.inputs, claimFormats: [bad, base.inputs.claimFormats[1]] });
        await reject({ ...base.inputs, claimFormats: [base.inputs.claimFormats[0], bad] });
      }
    });

    it("disabled slot ignores an out-of-range claimFormat and outputs zero (expected to pass)", async () => {
      const one = buildFixture([{ name: "dateOfBirth", format: JSONLD_FORMAT.isoDate }]);
      for (const bad of [6n, FIELD - 1n, 1n << 200n]) {
        const w = await accept({ ...one.inputs, claimFormats: [one.inputs.claimFormats[0], bad] });
        assert.equal((await out(w))[1], 0n);
        assert.equal((await out(w))[3], 0n);
      }
    });

    const near: Array<[string, (inputs: JsonLdInputs, v: bigint) => JsonLdInputs]> = [
      ["linePos[0]", (i, v) => ({ ...i, linePos: [v, i.linePos[1]] })],
      ["linePos[1]", (i, v) => ({ ...i, linePos: [i.linePos[0], v] })],
      ["csPos", (i, v) => ({ ...i, csPos: v })],
      ["deviceKeyLinePos", (i, v) => ({ ...i, deviceKeyLinePos: v })],
      ["jwkXPos", (i, v) => ({ ...i, jwkXPos: v })],
      ["jwkYPos", (i, v) => ({ ...i, jwkYPos: v })],
    ];
    const realPos = (name: string, i: JsonLdInputs): bigint =>
      ({ "linePos[0]": i.linePos[0], "linePos[1]": i.linePos[1], csPos: i.csPos, deviceKeyLinePos: i.deviceKeyLinePos, jwkXPos: i.jwkXPos, jwkYPos: i.jwkYPos } as Record<string, bigint>)[name];

    for (const [name, set] of near) {
      it(`ATTACK: ${name} wrapped around the field modulus or past 2^12`, async () => {
        const real = realPos(name, base.inputs);
        for (const v of [FIELD - 1n, FIELD - real, FIELD - real - 1n, real + 4096n, real + (1n << 64n), 4095n, 4096n, FIELD - 4096n]) {
          if (v === real) continue;
          await reject(set(base.inputs, v));
        }
      });
    }

    it("ATTACK: subjectLength wrapped (comparator over-range inputs)", async () => {
      const len = base.inputs.subjectLength;
      for (const v of [0n, 129n, 255n, 256n + len, FIELD - 1n, FIELD - len, FIELD - 71n]) {
        await reject({ ...base.inputs, subjectLength: v });
      }
    });

    it("ATTACK: deviceKeyValueLength wrapped (comparator over-range inputs)", async () => {
      const len = base.inputs.deviceKeyValueLength;
      for (const v of [0n, 253n, 255n, 256n + len, FIELD - 1n, FIELD - len, FIELD - 4n]) {
        await reject({ ...base.inputs, deviceKeyValueLength: v });
      }
    });

    it("ATTACK: wrapped lengths on a disabled slot do not smuggle anything (rejected or zero outputs)", async () => {
      const one = buildFixture([{ name: "dateOfBirth", format: JSONLD_FORMAT.isoDate }]);
      for (const v of [FIELD - 1n, 32n, 65n, 1n << 70n]) {
        for (const set of [
          (i: JsonLdInputs) => ({ ...i, nameLengths: [i.nameLengths[0], v] }),
          (i: JsonLdInputs) => ({ ...i, valueLengths: [i.valueLengths[0], v] }),
        ]) {
          let w: bigint[] | undefined;
          try {
            w = await circuit.calculateWitness(set(one.inputs) as any);
          } catch (e) {
            assert.match(String(e), /Assert Failed|Error in template/, `not a circuit failure: ${e}`);
            continue;
          }
          assert.equal((await out(w))[1], 0n, "disabled slot leaked a value");
          assert.equal((await out(w))[3], 0n, "disabled slot leaked an identity hash");
        }
      }
    });
  });

  // ---- 7. device key / JWK confusion -----------------------------------------------------

  describe("device key JWK", () => {
    const xs = () => b64c(KEY.x);
    const ys = () => b64c(KEY.y);

    it("control: y before x, extra members and different anchors are accepted with the right key", async () => {
      const json = `{"kid":"k1","y":"${ys()}","kty":"EC","crv":"P-256","x":"${xs()}"}`;
      const w = await accept(withDeviceKey(json));
      assert.equal((await out(w))[4], KEY.x);
      assert.equal((await out(w))[5], KEY.y);
    });

    it("ATTACK: non-canonical coordinates (x or y at or above the P-256 prime)", async () => {
      const bad = [P256_P, P256_P + 5n, (1n << 256n) - 1n];
      for (const v of bad) {
        await reject(withDeviceKey(jwkJson(b64c(v), ys())));
        await reject(withDeviceKey(jwkJson(xs(), b64c(v))));
      }
      // control: the largest canonical value is accepted
      await accept(withDeviceKey(jwkJson(b64c(P256_P - 1n), ys())));
    });

    it("ATTACK: an anchor inside an escaped string member is not a match", async () => {
      const evilX = b64c(7n);
      const json = `{"kid":"\\"x\\":\\"${evilX}\\"","kty":"EC","crv":"P-256","x":"${xs()}","y":"${ys()}"}`;
      const honest = withDeviceKey(json);
      const w = await accept(honest);
      assert.equal((await out(w))[4], KEY.x);
      const inner = json.indexOf(`"x\\":`);
      assert.ok(inner > 0);
      await reject({ ...honest, jwkXPos: BigInt(inner) });
      await reject({ ...honest, jwkXPos: BigInt(inner - 1) });
      await reject({ ...honest, jwkXPos: BigInt(json.indexOf(evilX) - 5) });
    });

    it("ATTACK: coordinate that is not exactly 43 characters (42 or 44)", async () => {
      await accept(withDeviceKey(jwkJson(xs(), ys())));
      await reject(withDeviceKey(jwkJson(xs().slice(0, 42), ys())));
      await reject(withDeviceKey(jwkJson(xs() + "A", ys())));
      await reject(withDeviceKey(jwkJson(xs(), ys().slice(0, 42))));
      await reject(withDeviceKey(jwkJson(xs(), ys() + "A")));
    });

    it("ATTACK: x anchor pointing into the y member, or at the end of the JSON", async () => {
      const json = jwkJson(xs(), ys());
      const honest = withDeviceKey(json);
      await accept(honest);
      await reject({ ...honest, jwkXPos: honest.jwkYPos, jwkYPos: honest.jwkXPos });
      await reject({ ...honest, jwkXPos: BigInt(json.length - 6), jwkYPos: BigInt(json.length - 6) });
      await reject({ ...honest, jwkXPos: honest.jwkXPos, jwkYPos: honest.jwkXPos });
      await reject({ ...honest, jwkXPos: honest.jwkYPos, jwkYPos: honest.jwkYPos });
    });

    it("ATTACK: deviceKeyValueLength off the real literal length", async () => {
      const len = base.inputs.deviceKeyValueLength;
      for (const v of [len - 1n, len - 4n, len + 1n, len + 4n]) {
        await reject({ ...base.inputs, deviceKeyValueLength: v });
      }
    });

    it("ATTACK: base64 padding or standard-alphabet characters in the literal", async () => {
      const json = jwkJson(xs(), ys());
      const std = Buffer.from(json).toString("base64url");
      for (const tail of ["=", "==", "+", "/"]) {
        const b64 = std + tail;
        const doc = base.nquads.replace(DK_B64, b64);
        await reject(
          forge(doc, {
            deviceKeyValue: bytesPadded(b64, 252),
            deviceKeyValueLength: BigInt(b64.length),
            jwkXPos: BigInt(json.indexOf('"x":"')),
            jwkYPos: BigInt(json.indexOf('"y":"')),
          }),
        );
      }
    });

    it("ATTACK: a deviceKey literal longer than maxDeviceKeyLen", async () => {
      const json = `{"pad":"${"A".repeat(120)}","kty":"EC","crv":"P-256","x":"${xs()}","y":"${ys()}"}`;
      const b64 = Buffer.from(json).toString("base64url");
      assert.ok(b64.length > 252);
      const doc = base.nquads.replace(DK_B64, b64);
      await reject(
        forge(doc, {
          deviceKeyValue: bytesPadded(b64.slice(0, 252), 252),
          deviceKeyValueLength: 252n,
          jwkXPos: BigInt(json.indexOf('"x":"')),
          jwkYPos: BigInt(json.indexOf('"y":"')),
        }),
      );
    });

    it("RESIDUAL (expected to pass): duplicated \"x\":\" anchors let the prover pick either coordinate", async () => {
      // Precondition: the signed JWK has each anchor exactly once (buildJsonLdPrepareInputs).
      // A JWK the issuer signed with a duplicate member is not constrained further.
      const other = b64c(7n);
      const json = `{"kty":"EC","crv":"P-256","n":{"x":"${other}"},"x":"${xs()}","y":"${ys()}"}`;
      const first = json.indexOf('"x":"');
      const second = json.indexOf('"x":"', first + 1);
      assert.ok(second > first);
      const a = await accept(withDeviceKey(json, { x: first }));
      assert.equal((await out(a))[4], 7n);
      const b = await accept(withDeviceKey(json, { x: second }));
      assert.equal((await out(b))[4], KEY.x);
    });
  });

  // ---- 8. disabled slots -----------------------------------------------------------------

  describe("disabled slots", () => {
    it("claimFlags 0 with full names, values and formats yields zero outputs and smuggles no identity", async () => {
      const one = buildFixture([{ name: "dateOfBirth", format: JSONLD_FORMAT.isoDate }]);
      const loaded = setSlot(one.inputs, 1, {
        name: "nationality",
        value: "Ruritanian",
        format: JSONLD_FORMAT.digest64,
        linePos: lineAt(base.nquads, S, "nationality"),
        flag: 0n,
      });
      const w = await accept(loaded);
      assert.equal((await out(w))[1], 0n);
      assert.equal((await out(w))[3], 0n);
      // control: flagged on, the same slot yields a non-zero identity and value
      const on = await accept(setSlot(loaded, 1, { flag: 1n }));
      assert.notEqual((await out(on))[3], 0n);
      assert.notEqual((await out(on))[1], 0n);
    });

    it("claimFlags 0 with garbage that matches nothing in the document yields zero outputs", async () => {
      const one = buildFixture([{ name: "dateOfBirth", format: JSONLD_FORMAT.isoDate }]);
      const w = await accept({
        ...one.inputs,
        linePos: [one.inputs.linePos[0], 1234n],
        names: [one.inputs.names[0], bytesPadded('<>" \\', 31)],
        nameLengths: [one.inputs.nameLengths[0], 5n],
        values: [one.inputs.values[0], bytesPadded('"\\\n\r', 64)],
        valueLengths: [one.inputs.valueLengths[0], 4n],
        claimFormats: [one.inputs.claimFormats[0], BigInt(JSONLD_FORMAT.digest64)],
      });
      assert.equal((await out(w))[1], 0n);
      assert.equal((await out(w))[3], 0n);
    });

    it("both slots disabled: outputs zero, subject and deviceKey still pinned", async () => {
      const none = buildFixture([]);
      const w = await accept(none.inputs);
      assert.deepEqual([(await out(w))[0], (await out(w))[1], (await out(w))[2], (await out(w))[3]], [0n, 0n, 0n, 0n]);
      assert.equal((await out(w))[4], KEY.x);
      await reject({ ...none.inputs, csPos: none.inputs.csPos + 1n });
      await reject({ ...none.inputs, deviceKeyLinePos: 0n });
    });
  });

  // ---- 9. alphabet edges -----------------------------------------------------------------

  describe("alphabet edges", () => {
    for (const ch of [" ", ">", '"', ".", "#", "/", ":", "-", "@", "[", "`", "{", "\\", "\r"]) {
      it(`ATTACK: claim name containing ${JSON.stringify(ch)}`, async () => {
        const name = "date" + ch + "fBirth";
        const doc = base.nquads.replace("#dateOfBirth>", `#${name}>`);
        assert.notEqual(doc, base.nquads);
        const honest = forge(base.nquads);
        await accept(honest);
        const attack = forge(doc, {}, setSlot(base.inputs, 0, { name }));
        await reject(attack, /^NQuadsClaimLine$/);
      });
    }

    for (const ch of ["<", " ", '"', "\\", "\r", ">"]) {
      it(`ATTACK: credentialSubject IRI containing ${JSON.stringify(ch)}`, async () => {
        const bad = S.slice(0, 20) + ch + S.slice(21);
        const doc = base.nquads.replaceAll(S, bad);
        const forged = withDoc({ ...base.inputs, subject: bytesPadded(bad, 128) }, doc, base.proofHash, { subject: bad });
        await reject(forged, /^NQuadsSubject$/);
      });
    }
  });

  // ---- 10. signature ---------------------------------------------------------------------

  describe("signature", () => {
    const stranger = () => {
      const d = p256.utils.randomPrivateKey();
      const pub = p256.getPublicKey(d, false);
      const big = (b: Uint8Array) => b.reduce((n, v) => (n << 8n) | BigInt(v), 0n);
      return { d: big(d), x: big(pub.slice(1, 33)), y: big(pub.slice(33, 65)) };
    };

    it("ATTACK: a forged document signed by a stranger's key under the issuer's public key", async () => {
      const doc = tripleLine(S, B + "zzz", "last") + base.nquads;
      const forgedOk = forge(doc);
      await accept(forgedOk); // control: issuer-signed
      const key = stranger();
      const sig = signJsonLd(doc, base.proofHash, key);
      await reject({ ...forgedOk, sig_r: sig.r, sig_s_inverse: Fn.inv(sig.s) });
      // control: the stranger's own key verifies its own signature (pubKey is a public input)
      await accept({ ...forgedOk, sig_r: sig.r, sig_s_inverse: Fn.inv(sig.s), pubKeyX: key.x, pubKeyY: key.y });
    });

    it("ATTACK: degenerate signatures (r = 0, s^-1 = 0, r = n, r >= n)", async () => {
      const i = base.inputs;
      await reject({ ...i, sig_r: 0n });
      await reject({ ...i, sig_s_inverse: 0n });
      await reject({ ...i, sig_r: 0n, sig_s_inverse: 0n });
      await reject({ ...i, sig_r: FIELD });
      await reject({ ...i, sig_r: i.sig_r + FIELD });
      await reject({ ...i, sig_s_inverse: i.sig_s_inverse + 1n });
      await reject({ ...i, pubKeyX: 0n, pubKeyY: 0n });
    });

    it("RESIDUAL (expected to pass): a different proofHash under a signature over it still proves", async () => {
      // proofHash is private and not recomputed; the proof options are only bound through
      // whatever hash the issuer signed. Signing the other hash is what a different options
      // document would produce.
      const other = new Uint8Array(sha256(UTF8.encode("some other proof options")));
      const doc = base.nquads;
      const sig = signJsonLd(doc, other);
      const w = await accept({
        ...base.inputs,
        proofHash: Array.from(other, (b) => BigInt(b)),
        sig_r: sig.r,
        sig_s_inverse: Fn.inv(sig.s),
      });
      assert.equal((await out(w))[4], KEY.x);
    });

    it("ATTACK: proofHash entries outside 0..255", async () => {
      for (const delta of [256n, FIELD - 256n]) {
        const proofHash = [...base.inputs.proofHash];
        proofHash[3] = (proofHash[3] + delta) % FIELD;
        await reject({ ...base.inputs, proofHash });
      }
    });

    it("ATTACK: a signature over a proofHash that differs from the one supplied", async () => {
      const proofHash = [...base.inputs.proofHash];
      proofHash[31] = proofHash[31] ^ 0x80n;
      await reject({ ...base.inputs, proofHash });
    });
  });
});
