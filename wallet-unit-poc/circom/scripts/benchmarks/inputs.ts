import { nameToBuffer } from "../../src/show.ts";

/** A Show input as written by generate-inputs: every value a decimal string. */
export interface ShowInput {
  predicateLen: string;
  claimValues: string[];
  predicateClaimRefs: string[];
  predicateOps: string[];
  predicateRhsIsRef: string[];
  predicateRhsValues: string[];
  claimIdentifierHashes: string[];
  predicateClaimNames: string[][];
  predicateClaimNameLens: string[];
  predicateRhsClaimNames: string[][];
  predicateRhsClaimNameLens: string[];
  tokenTypes: string[];
  tokenValues: string[];
  exprLen: string;
  [k: string]: unknown;
}

export const OP = { LE: 0, GE: 1, EQ: 2 } as const;
const REF = 0;
const AND = 1;
const OR = 2;
const BIRTHDAY_SLOT = 1;
const BIRTHDAY = 1040605;
const NAME = "roc_birthday";

export interface Predicate {
  op: number;
  rhs: number;
}

export interface Policy {
  predicates: Predicate[];
  /** Postfix tokens as [type, value]. */
  tokens: [number, number][];
  expected: 0 | 1;
}

const TRUE_PREDICATES: Predicate[] = [
  { op: OP.LE, rhs: 1070101 },
  { op: OP.GE, rhs: 1000101 },
  { op: OP.EQ, rhs: BIRTHDAY },
];
const FALSE = { le: 1000101, ge: 1090101, eq: BIRTHDAY + 1 };

/** The policy workloads over the birthday claim; throws when it does not fit (m, t). */
export function policyFor(workload: string, m: number, t: number): Policy {
  const fit = (preds: number, tokens: number) => {
    if (m < preds || t < tokens) throw new Error(`${workload} needs M>=${preds}, T>=${tokens}; circuit is (${m},${t})`);
  };
  if (workload === "w1") {
    fit(1, 1);
    return { predicates: [TRUE_PREDICATES[0]], tokens: [[REF, 0]], expected: 1 };
  }
  if (workload === "w2") {
    // (P0 AND P1) OR (P2 AND P3): four comparisons, seven tokens, true through the left branch.
    fit(4, 7);
    return {
      predicates: [TRUE_PREDICATES[0], TRUE_PREDICATES[1], TRUE_PREDICATES[2], { op: OP.GE, rhs: FALSE.ge }],
      tokens: [[REF, 0], [REF, 1], [AND, 0], [REF, 2], [REF, 3], [AND, 0], [OR, 0]],
      expected: 1,
    };
  }
  if (workload === "w3") {
    fit(m, 2 * m - 1);
    const predicates = Array.from({ length: m }, (_, i) => TRUE_PREDICATES[i % 3]);
    const tokens: [number, number][] = [[REF, 0]];
    for (let i = 1; i < m; i++) tokens.push([REF, i], [AND, 0]);
    return { predicates, tokens, expected: 1 };
  }
  const single = workload.match(/^(eq|le|ge)_(true|false)$/);
  if (single) {
    fit(1, 1);
    const [, kind, truth] = single;
    const idx = { le: 0, ge: 1, eq: 2 }[kind as "le" | "ge" | "eq"];
    const pred = truth === "true" ? TRUE_PREDICATES[idx] : { op: TRUE_PREDICATES[idx].op, rhs: FALSE[kind as "le" | "ge" | "eq"] };
    return { predicates: [pred], tokens: [[REF, 0]], expected: truth === "true" ? 1 : 0 };
  }
  throw new Error(`unknown workload ${workload}`);
}

const pad = <T>(xs: T[], n: number, fill: T): T[] => [...xs, ...Array(Math.max(0, n - xs.length)).fill(fill)];

/** Re-pads a base input to (N, M, T) and installs the policy; wallet and registry fields are kept. */
export function repad(base: ShowInput, v: { n: number; m: number; t: number }, policy: Policy): ShowInput {
  const name = nameToBuffer(NAME);
  const zeros = Array(31).fill("0");
  const preds = policy.predicates;
  return {
    ...base,
    claimValues: pad(base.claimValues, v.n, "0"),
    claimIdentifierHashes: pad(base.claimIdentifierHashes, v.n, "0"),
    predicateLen: String(preds.length),
    predicateClaimRefs: pad(preds.map(() => String(BIRTHDAY_SLOT)), v.m, "0"),
    predicateOps: pad(preds.map((p) => String(p.op)), v.m, "0"),
    predicateRhsIsRef: Array(v.m).fill("0"),
    predicateRhsValues: pad(preds.map((p) => String(p.rhs)), v.m, "0"),
    predicateClaimNames: pad(preds.map(() => name.bytes.map(String)), v.m, zeros),
    predicateClaimNameLens: pad(preds.map(() => String(name.len)), v.m, "0"),
    predicateRhsClaimNames: Array.from({ length: v.m }, () => zeros),
    predicateRhsClaimNameLens: Array(v.m).fill("0"),
    tokenTypes: pad(policy.tokens.map(([ty]) => String(ty)), v.t, "0"),
    tokenValues: pad(policy.tokens.map(([, val]) => String(val)), v.t, "0"),
    exprLen: String(policy.tokens.length),
  };
}
