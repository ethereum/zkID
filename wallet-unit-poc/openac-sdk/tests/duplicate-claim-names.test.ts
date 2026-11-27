// The circuit binds claim slots to H(name), so duplicate names make predicate
// selection depend on disclosure order. Reject them while parsing credentials.

import { describe, it, expect } from "vitest";

import { compilePredicateExpression } from "../src/predicates.js";
import { Credential } from "../src/credential.js";
import { generateDummyCredential } from "../src/testing/index.js";
import type { PredicateExpression } from "../src/predicates.js";

const ADULT: PredicateExpression = { claim: "age", op: ">=", value: 18n, format: "uint" };

describe("duplicate claim names", () => {
  const cred = generateDummyCredential({
    size: "1k",
    claims: [
      { key: "age", value: "17" },
      { key: "age", value: "21" },
    ],
  });

  for (const [label, disclosures] of [
    ["issuer order", cred.disclosures],
    ["reordered", [...cred.disclosures].reverse()],
  ] as const) {
    it(`rejects duplicate names during parsing (${label})`, () => {
      expect(() => Credential.parse(cred.jwt, [...disclosures])).toThrow(
        expect.objectContaining({ code: "AMBIGUOUS_PAYLOAD" }),
      );
    });
  }

  it("rejects duplicates even when no predicate reads that name", () => {
    const unrelated = generateDummyCredential({
      size: "1k",
      claims: [
        { key: "age", value: "21" },
        { key: "nationality", value: "A" },
        { key: "nationality", value: "B" },
      ],
    });
    expect(() => Credential.parse(unrelated.jwt, unrelated.disclosures)).toThrow(
      expect.objectContaining({ code: "AMBIGUOUS_PAYLOAD" }),
    );
  });

  it("also rejects duplicates passed directly to predicate compilation", () => {
    const claim = (index: number, name: string) =>
      ({ index, name, salt: "", value: "1", raw: "", digest: "" });
    const claims = [claim(0, "age"), claim(1, "nationality"), claim(2, "nationality")];
    expect(() => compilePredicateExpression(ADULT, claims)).toThrow(
      expect.objectContaining({ code: "AMBIGUOUS_PAYLOAD" }),
    );
  });

  it("still compiles distinct names", () => {
    const ok = generateDummyCredential({
      size: "1k",
      claims: [
        { key: "age", value: "21" },
        { key: "age_", value: "17" },
      ],
    });
    const parsed = Credential.parse(ok.jwt, ok.disclosures);
    const compiled = compilePredicateExpression(ADULT, parsed.claims);
    expect(compiled.predicates[0]!.claimRef).toBe(0);
  });
});
