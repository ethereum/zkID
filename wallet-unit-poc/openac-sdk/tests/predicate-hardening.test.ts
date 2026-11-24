// Policy-compiler and verifier-side checks: unsafe numeric literals, operator x
// format combinations, sparse schemas.
//
// No SNARK: the Verifier gets a stub bridge, as in show-statement-binding.test.ts.

import { describe, it, expect } from "vitest";
import { p256 } from "@noble/curves/nist.js";

import { Verifier } from "../src/verifier.js";
import {
  buildShowStatementPublicValues,
  compilePredicateExpression,
  requiredNormalization,
} from "../src/index.js";
import { PredicateOp } from "../src/inputs/show-input-builder.js";
import { issuerPublicKeyToPoint } from "../src/inputs/issuer-key.js";
import { DEFAULT_SHOW_PARAMS } from "../src/types.js";
import { bigintToBase64url } from "../src/utils.js";
import type {
  ClaimNormalization,
  DisclosedClaim,
  ExpectedStatement,
  VerifyingKeys,
} from "../src/types.js";
import type { PredicateExpression } from "../src/predicates.js";

const claim = (index: number, name: string): DisclosedClaim => ({
  index,
  salt: "",
  name,
  value: "1",
  raw: "",
  digest: "",
});

const CLAIMS = [claim(0, "age"), claim(1, "limit")];

describe("1789506262: unsafe JS number literals", () => {
  const over = (value: bigint | number | string): PredicateExpression => ({
    claim: "age",
    op: "==",
    value,
    format: "uint",
  });

  it("rejects a number above 2^53 - 1", () => {
    expect(() => compilePredicateExpression(over(9007199254740993), CLAIMS)).toThrow(
      /safe integer.*bigint or a decimal string/s,
    );
  });

  it("rejects 2^53 itself and a negative unsafe number", () => {
    expect(() => compilePredicateExpression(over(2 ** 53), CLAIMS)).toThrow(/safe integer/);
    expect(() => compilePredicateExpression(over(-(2 ** 53)), CLAIMS)).toThrow(/safe integer/);
  });

  it("control: the same value as bigint or string keeps full precision", () => {
    for (const v of [9007199254740993n, "9007199254740993"]) {
      const c = compilePredicateExpression(over(v), CLAIMS);
      expect(c.predicates[0]!.rhs).toEqual({ kind: "literal", value: 9007199254740993n });
    }
  });

  it("control: a safe number still compiles", () => {
    const c = compilePredicateExpression(over(Number.MAX_SAFE_INTEGER), CLAIMS);
    expect(c.predicates[0]!.rhs).toEqual({ kind: "literal", value: 9007199254740991n });
  });
});

describe("1789512824: operator x format table", () => {
  const cmp = (op: "<=" | ">=" | "==", format: "uint" | "date" | "string"): PredicateExpression => ({
    claim: "age",
    op,
    compareTo: { claim: "limit" },
    format,
  });

  it.each(["<=", ">="] as const)("rejects %s over string", (op) => {
    expect(() => compilePredicateExpression(cmp(op, "string"), CLAIMS)).toThrow(
      /not allowed.*string/s,
    );
  });

  it("control: LE over uint and EQ over string compile", () => {
    expect(() => compilePredicateExpression(cmp("<=", "uint"), CLAIMS)).not.toThrow();
    expect(() => compilePredicateExpression(cmp("==", "string"), CLAIMS)).not.toThrow();
  });
});

// --- verifier side ---------------------------------------------------------

const toScalarString = (v: bigint) => "0x" + v.toString(16).padStart(64, "0");
const ISSUER = (() => {
  const pt = p256.ProjectivePoint.BASE.multiply(0x2a2an);
  return { kty: "EC" as const, crv: "P-256" as const, x: bigintToBase64url(pt.x), y: bigintToBase64url(pt.y) };
})();
const KEYS: VerifyingKeys = {
  prepareVerifyingKey: new Uint8Array(),
  showVerifyingKey: new Uint8Array(),
};
const NONCE = "nonce-0123456789abcdef";

function bridgeFor(expected: ExpectedStatement, actual: ClaimNormalization) {
  const point = issuerPublicKeyToPoint(ISSUER);
  const pad = (a: number[]) => [0, 1].map((i) => BigInt(a[i] ?? 0));
  const statement = buildShowStatementPublicValues(
    DEFAULT_SHOW_PARAMS,
    expected.nonce,
    expected.predicates,
    expected.logicExpression,
  );
  return {
    verify: async () => ({
      valid: true,
      preparePublicValues: [point.x, point.y, ...pad(actual.decodeFlags), ...pad(actual.claimFormats)].map(
        toScalarString,
      ),
      showPublicValues: [1n, ...statement].map(toScalarString),
    }),
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any;
}

async function verify(expected: ExpectedStatement, actual = expected.claimNormalization) {
  return new Verifier(bridgeFor(expected, actual)).verifyComponents(
    new Uint8Array(),
    new Uint8Array(),
    KEYS,
    new Uint8Array(),
    new Uint8Array(),
    expected,
  );
}

function expectedFor(expr: PredicateExpression): ExpectedStatement {
  const c = compilePredicateExpression(expr, CLAIMS);
  return {
    nonce: NONCE,
    predicates: c.predicates,
    logicExpression: c.logicExpression,
    claimNormalization: requiredNormalization(c),
  };
}

describe("1789512824: verifier checks the same table", () => {
  const stringEq = expectedFor({ claim: "age", op: "==", compareTo: { claim: "limit" }, format: "string" });

  it("fails closed on LE over a string-normalized slot", async () => {
    // Bypasses the compiler, as a hand-built ExpectedStatement would.
    const forged: ExpectedStatement = {
      ...stringEq,
      predicates: stringEq.predicates.map((p) => ({ ...p, op: PredicateOp.LE })),
    };
    const r = await verify(forged);
    expect(r.valid).toBe(false);
    expect(r.error).toMatch(/not allowed/);
  });

  it("control: EQ over string verifies", async () => {
    expect((await verify(stringEq)).valid).toBe(true);
  });

  it("control: LE over uint verifies", async () => {
    const r = await verify(expectedFor({ claim: "age", op: "<=", compareTo: { claim: "limit" }, format: "uint" }));
    expect(r.valid).toBe(true);
  });
});

describe("1789511071: sparse schemas", () => {
  const SPARSE = [claim(0, "age"), claim(1, "limit"), claim(5, "far")];
  const onFar: PredicateExpression = { claim: "far", op: "==", value: 1n, format: "uint" };

  it("sizes the normalization arrays by highest referenced index + 1", () => {
    const c = compilePredicateExpression(onFar, SPARSE);
    expect(c.decodeFlags).toEqual([0, 0, 0, 0, 0, 1]);
    expect(c.claimFormats).toHaveLength(6);
    expect(c.claimFormats[5]).toBe(1);
  });

  it("control: a dense schema keeps one slot per referenced index", () => {
    const c = compilePredicateExpression(
      { claim: "limit", op: "==", value: 1n, format: "uint" },
      CLAIMS,
    );
    expect(c.decodeFlags).toEqual([0, 1]);
  });

  it("verifier fails closed when a referenced slot has no expected format", async () => {
    const exp = expectedFor({ claim: "limit", op: "==", value: 1n, format: "uint" });
    const truncated: ExpectedStatement = {
      ...exp,
      claimNormalization: { decodeFlags: [0, 1], claimFormats: [1] },
    };
    const r = await verify(truncated, exp.claimNormalization);
    expect(r.valid).toBe(false);
    expect(r.error).toMatch(/no expected format/);
  });

  it("verifier rejects a read slot whose expected decodeFlag is 0", async () => {
    const exp = expectedFor({ claim: "limit", op: "==", value: 1n, format: "uint" });
    const undecoded: ExpectedStatement = {
      ...exp,
      claimNormalization: { decodeFlags: [0, 0], claimFormats: [1, 1] },
    };
    // The proof decoded the slot, as a holder's would; the expectation does not
    // say so, so the format comparison would be skipped without the check.
    const r = await verify(undecoded, exp.claimNormalization);
    expect(r.valid).toBe(false);
    expect(r.error).toMatch(/undecoded|decodeFlag/);
  });

  it("control: complete expected normalization verifies", async () => {
    const exp = expectedFor({ claim: "limit", op: "==", value: 1n, format: "uint" });
    expect((await verify(exp)).valid).toBe(true);
  });
});
