// Unit tests for the claim-normalization check that present() runs before it
// reuses a precomputed credential's normalized claim values.
//
// These do NOT run the SNARK. They compile predicate expressions and call the
// check directly, plus exercise the serialization round-trip that carries the
// normalization metadata.

import { describe, it, expect } from "vitest";

import {
  compilePredicateExpression,
  assertNormalizationSupports,
  checkNormalizationSupports,
} from "../src/predicates.js";
import { buildJwtCircuitInputs } from "../src/inputs/jwt-input-builder.js";
import { Credential } from "../src/credential.js";
import { generateDummyCredential } from "../src/testing/index.js";
import { JWT_PARAMS_BY_SIZE } from "../src/sizing.js";
import { deserializePrecomputed } from "../src/prover.js";
import { OpenACError } from "../src/errors.js";
import type { ClaimNormalization, DisclosedClaim } from "../src/types.js";
import type { PredicateExpression } from "../src/predicates.js";

const CLAIMS: DisclosedClaim[] = [
  { index: 0, salt: "", name: "age", value: "30", raw: "", digest: "" },
  { index: 1, salt: "", name: "birthdate", value: "0900101", raw: "", digest: "" },
];

// The normalization a precompute() over `expr` would record.
function normalizationFor(expr: PredicateExpression): ClaimNormalization {
  const compiled = compilePredicateExpression(expr, CLAIMS);
  return { decodeFlags: compiled.decodeFlags, claimFormats: compiled.claimFormats };
}

function check(precomputedWith: PredicateExpression, presentedWith: PredicateExpression) {
  assertNormalizationSupports(
    normalizationFor(precomputedWith),
    compilePredicateExpression(presentedWith, CLAIMS),
  );
}

const AGE_UINT: PredicateExpression = { claim: "age", op: ">=", value: 18n, format: "uint" };
const AGE_LE_UINT: PredicateExpression = { claim: "age", op: "<=", value: 18n, format: "uint" };
// String-format predicates compare claim to claim: the DSL has no string literals.
const AGE_STRING: PredicateExpression = {
  claim: "age",
  op: "==",
  compareTo: { claim: "birthdate" },
  format: "string",
};
const BIRTHDATE_DATE: PredicateExpression = {
  claim: "birthdate",
  op: "<=",
  value: "0900101",
  format: "date",
};

describe("assertNormalizationSupports", () => {
  it("accepts the same predicate it was precomputed with", () => {
    expect(() => check(AGE_UINT, AGE_UINT)).not.toThrow();
  });

  it("accepts a different comparison over the same claim and format", () => {
    expect(() => check(AGE_UINT, AGE_LE_UINT)).not.toThrow();
  });

  it("rejects a claim the precompute left undecoded", () => {
    // Precomputed over `age` only, so slot 1 holds 0 rather than the birthdate.
    expect(() => check(AGE_UINT, BIRTHDATE_DATE)).toThrowError(/undecoded/i);
  });

  it("reports the claim name of the undecoded slot", () => {
    expect(() => check(AGE_UINT, BIRTHDATE_DATE)).toThrowError(/birthdate/);
  });

  it("rejects a claim normalized under a different format", () => {
    expect(() => check(AGE_STRING, AGE_UINT)).toThrowError(/normalized as string/);
  });

  it("uses the CLAIM_FORMAT_MISMATCH error code", () => {
    try {
      check(AGE_UINT, BIRTHDATE_DATE);
      expect.unreachable("expected a mismatch");
    } catch (e) {
      expect(e).toBeInstanceOf(OpenACError);
      expect((e as OpenACError).code).toBe("CLAIM_FORMAT_MISMATCH");
    }
  });

  it("ignores claims no presented predicate reads", () => {
    // Precomputed over both claims, presented over one: the unread slot's
    // normalization is irrelevant.
    const both: PredicateExpression = { all: [AGE_UINT, BIRTHDATE_DATE] };
    expect(() => check(both, AGE_UINT)).not.toThrow();
  });
});

describe("deserializePrecomputed", () => {
  const legacy = {
    version: "0.1.0",
    prepareProof: "",
    prepareInstance: "",
    prepareWitness: "",
    credential: { jwt: "", disclosures: [], deviceBindingKey: { kty: "EC", crv: "P-256", x: "", y: "" } },
    birthdayClaimIndex: 0,
    birthdayClaim: "",
    deviceKey: { kty: "EC", crv: "P-256", x: "", y: "" },
    normalizedClaimValues: ["30", "0"],
  };

  const encode = (o: unknown) => new TextEncoder().encode(JSON.stringify(o));

  it("rejects a blob with no normalization metadata", () => {
    expect(() => deserializePrecomputed(encode(legacy))).toThrowError(/older SDK version/);
  });

  it("rejects a blob with no issuer key", () => {
    const claimNormalization = { decodeFlags: [1, 0], claimFormats: [1, 1] };
    expect(() => deserializePrecomputed(encode({ ...legacy, claimNormalization }))).toThrowError(
      /issuer key/,
    );
  });

  it("rejects a blob whose normalization metadata is not arrays", () => {
    const malformed = { ...legacy, claimNormalization: { decodeFlags: 1, claimFormats: 1 } };
    expect(() => deserializePrecomputed(encode(malformed))).toThrowError(OpenACError);
  });

  it("round-trips normalization metadata", () => {
    const claimNormalization = { decodeFlags: [1, 0], claimFormats: [1, 1] };
    const issuerPublicKey = { kty: "EC", crv: "P-256", x: "", y: "" };
    const restored = deserializePrecomputed(
      encode({ ...legacy, claimNormalization, issuerPublicKey }),
    );
    expect(restored.claimNormalization).toEqual(claimNormalization);
    expect(restored.issuerPublicKey).toEqual(issuerPublicKey);
    expect(restored.toJSON().claimNormalization).toEqual(claimNormalization);
  });
});

describe("precompute() normalization metadata", () => {
  // The metadata stored on a PrecomputedCredential must describe what the
  // circuit ran on, not what was requested: the input builder pads and
  // truncates both arrays to the circuit's claim slot count, and the verifier
  // reads the padded form back out of the proof's public IO.

  it("matches the arrays the input builder feeds the circuit", () => {
    const compiled = compilePredicateExpression(AGE_UINT, CLAIMS);
    const params = JWT_PARAMS_BY_SIZE["1k"];
    const maxClaims = params.maxMatches - 2;

    const cred = generateDummyCredential({ size: "1k" });
    const parsed = Credential.parse(cred.jwt, cred.disclosures);
    const inputs = buildJwtCircuitInputs(
      parsed,
      cred.issuerPublicKey,
      params,
      parsed.disclosureHashes,
      compiled.decodeFlags,
      compiled.claimFormats,
    );

    expect(inputs.decodeFlags).toHaveLength(maxClaims);
    expect(inputs.claimFormats).toHaveLength(maxClaims);
  });

  it("rejects a predicate on a claim slot the circuit does not have", () => {
    // A credential with more claims than the circuit has slots: a predicate on
    // a truncated slot has no value to read, so present() must refuse rather
    // than build a proof the verifier would reject.
    const stored: ClaimNormalization = { decodeFlags: [1, 1], claimFormats: [1, 1] };
    const beyond: ClaimNormalization = {
      decodeFlags: [1, 1, 1],
      claimFormats: [1, 1, 1],
    };
    expect(checkNormalizationSupports(stored, beyond)).toMatch(/undecoded/i);
  });
});
