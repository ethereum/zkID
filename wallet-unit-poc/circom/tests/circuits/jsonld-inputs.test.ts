import { strict as assert } from "assert";
import { buildJsonLdPrepareInputs, claimIdentifierHash, normalizeJsonLdValue, JSONLD_BASE, JSONLD_FORMAT } from "../../src/jsonld/build-inputs.ts";
import { FIXTURE_NQUADS, FIXTURE_PROOF_NQUADS, loadTestIssuer, proofHashOf, signJsonLd } from "../../src/jsonld/test-fixture.ts";
import { hashClaimName } from "../common/claim-identity.ts";

const issuer = loadTestIssuer();

function build(nquads: string, claims = [{ name: "dateOfBirth", format: JSONLD_FORMAT.isoDate }]) {
  const proofHash = proofHashOf(FIXTURE_PROOF_NQUADS());
  return buildJsonLdPrepareInputs({
    nquads,
    proofHash,
    signature: signJsonLd(nquads, proofHash),
    issuerPublicKey: { x: issuer.x, y: issuer.y },
    base: JSONLD_BASE,
    claims,
  });
}

describe("jsonld input builder", () => {
  it("builds inputs and meta for the fixture", () => {
    const { inputs, meta } = build(FIXTURE_NQUADS(), [
      { name: "dateOfBirth", format: JSONLD_FORMAT.isoDate },
      { name: "nationality", format: JSONLD_FORMAT.digest64 },
    ]);
    assert.equal(meta.normalizedClaimValues[0], 19900101n);
    assert.equal(inputs.claimFlags[1], 1n);
    assert.equal(inputs.doc.length, 2240);
  });

  it("rejects a document with two credentialSubject lines", () => {
    const doc = FIXTURE_NQUADS();
    const line = doc.split("\n").find((l) => l.includes("credentialSubject"))!;
    assert.throws(() => build(doc + line + "\n"), /exactly one credentialSubject line/);
  });

  it("rejects a claim name that occurs on two lines", () => {
    const doc = FIXTURE_NQUADS();
    const line = doc.split("\n").find((l) => l.includes("#dateOfBirth"))!;
    assert.throws(() => build(doc + line + "\n"), /exactly one line/);
  });

  it("rejects an unknown claim name", () => {
    assert.throws(() => build(FIXTURE_NQUADS(), [{ name: "nope", format: 4 }]), /exactly one line/);
  });

  it("rejects a requested value with an escape", () => {
    const doc = FIXTURE_NQUADS().replace('"Sample Holder"', '"Sample \\"Holder"');
    assert.throws(() => build(doc, [{ name: "name", format: 4 }]), /escapes are not supported/);
  });

  it("rejects a JWK whose x anchor is ambiguous", () => {
    const jwk = Buffer.from('{"kty":"EC","x":"a","x":"b","y":"c"}').toString("base64url");
    const doc = FIXTURE_NQUADS().replace(/#deviceKey> "[^"]*"/, `#deviceKey> "${jwk}"`);
    assert.throws(() => build(doc), /anchor "x":" must occur exactly once/);
  });

  it("rejects a signature by another key", () => {
    const doc = FIXTURE_NQUADS();
    const proofHash = proofHashOf(FIXTURE_PROOF_NQUADS());
    assert.throws(
      () =>
        buildJsonLdPrepareInputs({
          nquads: doc,
          proofHash,
          signature: signJsonLd(doc, proofHash),
          issuerPublicKey: { x: issuer.x ^ 1n, y: issuer.y },
          base: JSONLD_BASE,
          claims: [],
        }),
      /./,
    );
  });
});

describe("jsonld value normalization", () => {
  it("matches the circuit formats", () => {
    assert.equal(normalizeJsonLdValue(JSONLD_FORMAT.bool, "true"), 1n);
    assert.equal(normalizeJsonLdValue(JSONLD_FORMAT.uint, "42"), 42n);
    assert.equal(normalizeJsonLdValue(JSONLD_FORMAT.isoDate, "2008-10-27"), 20081027n);
    assert.equal(normalizeJsonLdValue(JSONLD_FORMAT.rocDate, "0970101"), 970101n);
    assert.equal(normalizeJsonLdValue(JSONLD_FORMAT.string, "TW"), 21591n);
    assert.ok(normalizeJsonLdValue(JSONLD_FORMAT.digest64, "Ruritanian") < 2n ** 64n);
  });
});

describe("jsonld claimIdentifierHash", () => {
  // The circuits run over secq256r1, so the JS port is checked against the circuit itself.
  it("matches HashBytesToFieldWithLen run in the circuit", async () => {
    for (const name of ["dateOfBirth", "nationality", "a"]) {
      assert.equal(claimIdentifierHash(name), await hashClaimName(name), name);
    }
  });
});
