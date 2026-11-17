// Focused unit tests for the Show statement-binding logic that defeats
// policy-swap and replay attacks (see verifier.ts / inputs/show-statement.ts).
//
// These do NOT run the SNARK: they feed the Verifier a stub WASM bridge that
// returns crafted `showPublicValues` formatted exactly as the real WASM does
// (Rust `{:?}` on a secq256r1 scalar => big-endian, 0x-prefixed, 64 hex chars),
// then assert the verifier accepts only when the proof's bound public values
// match the verifier's expected nonce + policy.

import { describe, it, expect } from "vitest";
import { p256 } from "@noble/curves/nist.js";

import { Verifier } from "../src/verifier.js";
import {
  computeMessageHash,
  buildShowStatementPublicValues,
  compilePredicateExpression,
  requiredNormalization,
  acceptRevocationRoots,
  acceptIssuerRoots,
} from "../src/index.js";
import { NAME_ID_LEN } from "../src/inputs/show-statement.js";
import { createIssuerRegistry, toLimbs } from "../src/issuer-hiding.js";
import { DEFAULT_SHOW_PARAMS } from "../src/types.js";
import {
  P256_SCALAR_ORDER,
  sha256Hash,
  bytesToBigInt,
  bigintToBase64url,
} from "../src/utils.js";
import type {
  ClaimNormalization,
  DisclosedClaim,
  EcdsaPublicKey,
  ExpectedStatement,
  VerifyingKeys,
} from "../src/types.js";
import type { PredicateExpression } from "../src/predicates.js";

// Minimal claim set: name -> index mapping the verifier derives from the credential.
const CLAIMS: DisclosedClaim[] = [
  { index: 0, salt: "", name: "roc_birthday", value: "0900101", raw: "", digest: "" },
  { index: 1, salt: "", name: "roc_max", value: "0950101", raw: "", digest: "" },
];

const POLICY: PredicateExpression = {
  claim: "roc_birthday",
  op: "<=",
  compareTo: { claim: "roc_max" },
};

const OTHER_POLICY: PredicateExpression = {
  claim: "roc_birthday",
  op: ">=",
  value: 800000,
};

const DUMMY_KEYS: VerifyingKeys = {
  prepareVerifyingKey: new Uint8Array(),
  showVerifyingKey: new Uint8Array(),
};

/** Format a bigint the way the WASM verify formats a scalar: 0x + 64-char big-endian hex. */
function toScalarString(v: bigint): string {
  return "0x" + v.toString(16).padStart(64, "0");
}

/**
 * Build a stub WasmBridge whose `verify` returns a fixed public-value vector.
 * Only `verify` is exercised by the Verifier.
 */
function stubBridge(
  showPublicValues: string[],
  valid = true,
  normalization: ClaimNormalization = compiledNormalization,
) {
  return {
    verify: async () => ({
      valid,
      preparePublicValues: preparePublicValuesFor(normalization).map(toScalarString),
      showPublicValues,
      error: valid ? undefined : "snark failed",
    }),
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any;
}

/**
 * The Prepare public IO a JWT proof with two claim slots exposes:
 * [decodeFlags[2], claimFormats[2]] = 4 values (2n). Claim values, the device
 * key and the issuer key are private and reach Show through comm_W_shared.
 */
function preparePublicValuesFor(normalization: ClaimNormalization): bigint[] {
  const pad = (a: number[]) =>
    [0, 1].map((i) => BigInt(a[i] ?? 0));
  return [
    ...pad(normalization.decodeFlags),
    ...pad(normalization.claimFormats),
  ];
}

// A revocation root above 2^128, so both limbs are non-zero.
const REVOCATION_ROOT = (123n << 128n) | 456n;

/** The Show public values: [expressionResult, issuerRoot[hi, lo], revocationRoot[hi, lo], ...statement]. */
function publicValuesFor(
  nonce: string,
  predicates: PredicateExpression,
  expressionResult: boolean,
  issuerRoot: bigint = ISSUER_ROOT,
  revocationRoot: bigint = REVOCATION_ROOT,
): string[] {
  const compiled = compilePredicateExpression(predicates, CLAIMS);
  const statement = buildShowStatementPublicValues(
    DEFAULT_SHOW_PARAMS,
    nonce,
    compiled.predicates,
    compiled.logicExpression,
  );
  return [
    expressionResult ? 1n : 0n,
    ...toLimbs(issuerRoot),
    ...toLimbs(revocationRoot),
    ...statement,
  ].map(
    toScalarString,
  );
}

// Two distinct P-256 keys, standing in for a known issuer and an unknown one.
function keyFromScalar(k: bigint): EcdsaPublicKey {
  const point = p256.ProjectivePoint.BASE.multiply(k);
  const enc = (v: bigint) => bigintToBase64url(v);
  return { kty: "EC", crv: "P-256", x: enc(point.x), y: enc(point.y) };
}

const KNOWN_ISSUER = keyFromScalar(0x2a2an);
const OTHER_ISSUER = keyFromScalar(0x9f9fn);
const ISSUER_ROOT = createIssuerRegistry([KNOWN_ISSUER, OTHER_ISSUER]).root;
const OTHER_ROOT = createIssuerRegistry([OTHER_ISSUER]).root;

const NONCE = "session-nonce-abc";
const compiledPolicy = compilePredicateExpression(POLICY, CLAIMS);
const compiledNormalization = requiredNormalization(compiledPolicy);
const expected: ExpectedStatement = {
  nonce: NONCE,
  predicates: compiledPolicy.predicates,
  logicExpression: compiledPolicy.logicExpression,
  claimNormalization: compiledNormalization,
  isValidIssuerRoot: acceptIssuerRoots([ISSUER_ROOT]),
  isValidRevocationRoot: acceptRevocationRoots([REVOCATION_ROOT]),
};

async function verifyWith(showPublicValues: string[], exp: ExpectedStatement = expected) {
  const verifier = new Verifier(stubBridge(showPublicValues, true));
  return verifier.verifyComponents(
    new Uint8Array(),
    new Uint8Array(),
    DUMMY_KEYS,
    new Uint8Array(),
    new Uint8Array(),
    exp,
  );
}

describe("Show statement binding: helpers", () => {
  it("computeMessageHash matches sha256(nonce) mod scalar order", () => {
    const expectedHash =
      bytesToBigInt(sha256Hash(new TextEncoder().encode(NONCE))) % P256_SCALAR_ORDER;
    expect(computeMessageHash(NONCE)).toBe(expectedHash);
  });

  it("buildShowStatementPublicValues has the documented order and length", () => {
    const compiled = compilePredicateExpression(POLICY, CLAIMS);
    const pv = buildShowStatementPublicValues(
      DEFAULT_SHOW_PARAMS,
      NONCE,
      compiled.predicates,
      compiled.logicExpression,
    );
    // messageHash + predicateLen + exprLen (3) + 4 scalars/predicate
    // (claimRef, op, rhsIsRef, rhsValue) + 2 name buffers/predicate (LHS+RHS,
    // NAME_ID_LEN bytes each) + 2 name lengths/predicate + 2*maxLogicTokens tokens.
    const p = DEFAULT_SHOW_PARAMS;
    expect(pv.length).toBe(
      3 + 6 * p.maxPredicates + 2 * p.maxPredicates * NAME_ID_LEN + 2 * p.maxLogicTokens,
    );
    expect(pv[0]).toBe(computeMessageHash(NONCE)); // first element is the nonce hash
  });
});

describe("Show statement binding: verifier enforcement", () => {
  it("accepts a proof whose public values match the expected nonce + policy", async () => {
    const result = await verifyWith(publicValuesFor(NONCE, POLICY, true));
    expect(result.valid).toBe(true);
    expect(result.expressionResult).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it("reports the revocation root", async () => {
    const result = await verifyWith(publicValuesFor(NONCE, POLICY, true));
    expect(result.revocationRoot).toBe(REVOCATION_ROOT);
  });

  it("rejects a revocation root the verifier does not accept", async () => {
    const result = await verifyWith(publicValuesFor(NONCE, POLICY, true), {
      ...expected,
      isValidRevocationRoot: async () => false,
    });
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/Revocation root/);
  });

  it("checks the revocation root alone, since one registry serves every issuer", async () => {
    const seen: unknown[][] = [];
    const result = await verifyWith(publicValuesFor(NONCE, POLICY, true), {
      ...expected,
      isValidRevocationRoot: (...args: unknown[]) => {
        seen.push(args);
        return args[0] === REVOCATION_ROOT;
      },
    });
    expect(result.valid).toBe(true);
    expect(seen).toEqual([[REVOCATION_ROOT]]);
  });

  it("reads the revocation root from its own limbs, after the issuer root", async () => {
    const result = await verifyWith(
      publicValuesFor(NONCE, POLICY, true, OTHER_ROOT, REVOCATION_ROOT),
      { ...expected, isValidIssuerRoot: acceptIssuerRoots([OTHER_ROOT]) },
    );
    expect(result.valid).toBe(true);
    expect(result.issuerRoot).toBe(OTHER_ROOT);
    expect(result.revocationRoot).toBe(REVOCATION_ROOT);
  });

  it("rejects a non-canonical revocation root limb", async () => {
    const values = publicValuesFor(NONCE, POLICY, true);
    values[3] = toScalarString(1n << 128n);
    const result = await verifyWith(values);
    expect(result.valid).toBe(false);
    expect(result.revocationRoot).toBeNull();
  });

  it("fails closed when the root check throws", async () => {
    const result = await verifyWith(publicValuesFor(NONCE, POLICY, true), {
      ...expected,
      isValidRevocationRoot: () => {
        throw new Error("rpc down");
      },
    });
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/rpc down/);
  });

  it("reports expressionResult=false when the bound result bit is zero", async () => {
    const result = await verifyWith(publicValuesFor(NONCE, POLICY, false));
    expect(result.valid).toBe(true);
    expect(result.expressionResult).toBe(false);
  });

  it("rejects a replay: proof bound to a different nonce", async () => {
    const result = await verifyWith(publicValuesFor("a-stale-session-nonce", POLICY, true));
    expect(result.valid).toBe(false);
    expect(result.expressionResult).toBeNull();
    expect(result.error).toMatch(/nonce/i);
  });

  it("rejects a policy swap: proof bound to a different policy", async () => {
    const result = await verifyWith(publicValuesFor(NONCE, OTHER_POLICY, true));
    expect(result.valid).toBe(false);
    expect(result.expressionResult).toBeNull();
    expect(result.error).toMatch(/policy/i);
  });

  it("rejects when the SNARK itself is invalid, regardless of expectation", async () => {
    const verifier = new Verifier(stubBridge(publicValuesFor(NONCE, POLICY, true), false));
    const result = await verifier.verifyComponents(
      new Uint8Array(),
      new Uint8Array(),
      DUMMY_KEYS,
      new Uint8Array(),
      new Uint8Array(),
      expected,
    );
    expect(result.valid).toBe(false);
  });

  it("rejects when the proof exposes the wrong number of public values", async () => {
    const truncated = publicValuesFor(NONCE, POLICY, true).slice(0, 5);
    const result = await verifyWith(truncated);
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/size mismatch/i);
  });
});

describe("Issuer hiding: root reporting and acceptance", () => {
  it("reports the issuer root the proof was built against", async () => {
    const result = await verifyWith(publicValuesFor(NONCE, POLICY, true));
    expect(result.valid).toBe(true);
    expect(result.issuerRoot).toBe(ISSUER_ROOT);
  });

  it("accepts when isValidIssuerRoot accepts the root", async () => {
    const result = await verifyWith(publicValuesFor(NONCE, POLICY, true), {
      ...expected,
      isValidIssuerRoot: async (root) => root === ISSUER_ROOT,
    });
    expect(result.valid).toBe(true);
  });

  it("rejects a root the verifier does not accept", async () => {
    const result = await verifyWith(publicValuesFor(NONCE, POLICY, true, OTHER_ROOT), {
      ...expected,
      isValidIssuerRoot: (root) => root === ISSUER_ROOT,
    });
    expect(result.valid).toBe(false);
    expect(result.issuerRoot).toBeNull();
    expect(result.error).toMatch(/issuer root/i);
  });

  it("rejects an issuer root outside the verifier's accepted roots by default", async () => {
    const result = await verifyWith(publicValuesFor(NONCE, POLICY, true, OTHER_ROOT));
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/Issuer root is not accepted/);
  });

  it("fails closed when the issuer root check throws", async () => {
    const result = await verifyWith(publicValuesFor(NONCE, POLICY, true), {
      ...expected,
      isValidIssuerRoot: async () => {
        throw new Error("rpc down");
      },
    });
    expect(result.valid).toBe(false);
    expect(result.issuerRoot).toBeNull();
    expect(result.error).toMatch(/Issuer root check failed: rpc down/);
  });

  it("rejects a non-canonical root limb", async () => {
    const values = publicValuesFor(NONCE, POLICY, true);
    values[1] = toScalarString(1n << 128n);
    const result = await verifyWith(values);
    expect(result.valid).toBe(false);
  });

  it("reports no issuer root when verification fails", async () => {
    const result = await verifyWith(publicValuesFor("a-stale-session-nonce", POLICY, true));
    expect(result.valid).toBe(false);
    expect(result.issuerRoot).toBeNull();
  });

  it("rejects an expected statement whose nonce is too short (Item 20)", async () => {
    const result = await verifyWith(publicValuesFor(NONCE, POLICY, true), {
      ...expected,
      nonce: "short",
    });
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/nonce/i);
  });

  it("fails closed when the Prepare proof exposes a public IO size no JWT circuit produces", async () => {
    const verifier = new Verifier({
      verify: async () => ({
        valid: true,
        preparePublicValues: ["0x01"],
        showPublicValues: publicValuesFor(NONCE, POLICY, true),
      }),
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any);
    const result = await verifier.verifyComponents(
      new Uint8Array(),
      new Uint8Array(),
      DUMMY_KEYS,
      new Uint8Array(),
      new Uint8Array(),
      expected,
    );
    expect(result.valid).toBe(false);
    expect(result.issuerRoot).toBeNull();
    expect(result.error).toMatch(/not a valid JWT circuit public IO size/i);
  });
});

describe("Claim normalization binding: verifier enforcement", () => {
  // The prover picks decodeFlags/claimFormats when it builds the Prepare proof.
  // These cases feed the verifier a proof whose SNARK verifies and whose nonce
  // and policy match, differing only in how the claim values were produced.

  async function verifyWithNormalization(normalization: ClaimNormalization) {
    const verifier = new Verifier(
      stubBridge(publicValuesFor(NONCE, POLICY, true), true, normalization),
    );
    return verifier.verifyComponents(
      new Uint8Array(),
      new Uint8Array(),
      DUMMY_KEYS,
      new Uint8Array(),
      new Uint8Array(),
      expected,
    );
  }

  it("accepts a proof normalized the way the policy requires", async () => {
    const result = await verifyWithNormalization(compiledNormalization);
    expect(result.valid).toBe(true);
  });

  it("rejects a claim the proof left undecoded", async () => {
    // An undecoded slot holds 0, so the policy was evaluated against 0 rather
    // than the credential's claim value.
    const result = await verifyWithNormalization({
      decodeFlags: [0, 0],
      claimFormats: compiledNormalization.claimFormats,
    });
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/normalization/i);
    expect(result.error).toMatch(/undecoded/i);
  });

  it("rejects a claim normalized under a different format", async () => {
    const result = await verifyWithNormalization({
      decodeFlags: compiledNormalization.decodeFlags,
      claimFormats: [1, 1],
    });
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/normalization/i);
  });

  it("reports no issuer root when the normalization is rejected", async () => {
    const result = await verifyWithNormalization({
      decodeFlags: [0, 0],
      claimFormats: compiledNormalization.claimFormats,
    });
    expect(result.issuerRoot).toBeNull();
    expect(result.expressionResult).toBeNull();
  });

  it("accepts a proof that decoded more claims than the policy reads", async () => {
    // Preparing for a wider set of predicates than this verifier asks about is
    // legitimate: the slots this policy does not read never reach a comparison.
    const narrowPolicy: PredicateExpression = {
      claim: "roc_birthday",
      op: "<=",
      value: "0950101",
      format: "date",
    };
    const narrow = compilePredicateExpression(narrowPolicy, CLAIMS);
    const narrowExpected: ExpectedStatement = {
      nonce: NONCE,
      predicates: narrow.predicates,
      logicExpression: narrow.logicExpression,
      claimNormalization: requiredNormalization(narrow),
      isValidIssuerRoot: acceptIssuerRoots([ISSUER_ROOT]),
      isValidRevocationRoot: acceptRevocationRoots([REVOCATION_ROOT]),
    };
    expect(narrow.decodeFlags).toEqual([1, 0]);

    // The proof decoded both slots; the policy reads only the first.
    const verifier = new Verifier(
      stubBridge(
        publicValuesFor(NONCE, narrowPolicy, true),
        true,
        compiledNormalization,
      ),
    );
    const result = await verifier.verifyComponents(
      new Uint8Array(),
      new Uint8Array(),
      DUMMY_KEYS,
      new Uint8Array(),
      new Uint8Array(),
      narrowExpected,
    );
    expect(result.valid).toBe(true);
  });
});
