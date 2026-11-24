import assert from "assert";
import { policyFor, repad, type ShowInput } from "../../scripts/benchmarks/inputs.ts";

const base: ShowInput = {
  deviceKeyX: "1", deviceKeyY: "2", sig_r: "3", sig_s_inverse: "4", messageHash: "5",
  predicateLen: "1",
  claimValues: ["7", "1040605"],
  predicateClaimRefs: ["1", "0"],
  predicateOps: ["0", "2"],
  predicateRhsIsRef: ["0", "0"],
  predicateRhsValues: ["1070101", "7"],
  claimIdentifierHashes: ["10", "11"],
  predicateClaimNames: [Array(31).fill("9"), Array(31).fill("0")],
  predicateClaimNameLens: ["12", "0"],
  predicateRhsClaimNames: [Array(31).fill("0"), Array(31).fill("0")],
  predicateRhsClaimNameLens: ["0", "0"],
  tokenTypes: Array(8).fill("0"),
  tokenValues: Array(8).fill("0"),
  exprLen: "1",
  issuerKeyX: "1", issuerKeyY: "1", issuerTreeDepth: "8", issuerTreeIndex: "0", issuerTreeSiblings: [],
  revocationCommitment: ["0", "0"], revocationSecret: ["0", "0"], revocationLeafValue: ["0", "0"],
  revocationLeafNextValue: ["0", "0"], revocationLeafIndex: "0", revocationDepth: "0", revocationSiblings: [],
};

describe("policies", () => {
  it("w1 is one LE predicate", () => {
    const p = policyFor("w1", 2, 8);
    assert.strictEqual(p.predicates.length, 1);
    assert.deepStrictEqual(p.tokens, [[0, 0]]);
    assert.strictEqual(p.expected, 1);
  });

  it("w2 has four comparisons and seven postfix tokens", () => {
    const p = policyFor("w2", 4, 7);
    assert.strictEqual(p.predicates.length, 4);
    assert.strictEqual(p.tokens.length, 7);
    assert.ok(p.tokens.some(([t]) => t === 2), "uses OR");
    assert.ok(p.tokens.some(([t]) => t === 1), "uses AND");
  });

  it("w3 fills every predicate and token slot of a (M, 2M-1) circuit", () => {
    const p = policyFor("w3", 8, 15);
    assert.strictEqual(p.predicates.length, 8);
    assert.strictEqual(p.tokens.length, 15);
  });

  it("rejects a policy that does not fit the capacity", () => {
    assert.throws(() => policyFor("w2", 2, 8));
    assert.throws(() => policyFor("w3", 16, 8));
  });

  it("builds true and false single-predicate checks", () => {
    assert.strictEqual(policyFor("le_true", 2, 8).expected, 1);
    assert.strictEqual(policyFor("ge_false", 2, 8).expected, 0);
    assert.strictEqual(policyFor("eq_true", 2, 8).predicates[0].op, 2);
  });
});

describe("repad", () => {
  it("pads claims, predicates, tokens and keeps the wallet fields", () => {
    const out = repad(base, { n: 8, m: 4, t: 7 }, policyFor("w2", 4, 7));
    assert.strictEqual(out.claimValues.length, 8);
    assert.strictEqual(out.claimIdentifierHashes.length, 8);
    assert.strictEqual(out.predicateClaimRefs.length, 4);
    assert.strictEqual(out.predicateClaimNames.length, 4);
    assert.strictEqual(out.predicateClaimNames[0].length, 31);
    assert.strictEqual(out.tokenTypes.length, 7);
    assert.strictEqual(out.predicateLen, "4");
    assert.strictEqual(out.exprLen, "7");
    assert.strictEqual(out.claimValues[1], "1040605");
    assert.strictEqual(out.sig_r, "3");
  });
});
