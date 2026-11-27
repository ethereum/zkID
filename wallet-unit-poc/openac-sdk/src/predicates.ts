// High-level typed predicate DSL. Compiles to the low-level circuit
// representation in show-input-builder.ts and jwt-input-builder.ts.
//
// Format codes match jwt.circom (line 50):
//   0=bool, 1=uint, 2=iso_date, 3=roc_date, 4=string
// We expose three formats to consumers: "uint", "date", "string".
// "date" -> claimFormat=3 (roc_date), "uint" -> claimFormat=1, "string" ->
// claimFormat=4. Every claim referenced by a predicate is decoded
// (decodeFlag=1) so its value is extracted and normalized before comparison.

import { InputError } from "./errors.js";
import {
  PredicateOp,
  LogicToken,
  type PredicateSpec,
} from "./inputs/show-input-builder.js";
import type { ClaimNormalization, DisclosedClaim } from "./types.js";

export type Comparator = "<=" | ">=" | "==";
export type ClaimFormatHint = "uint" | "date" | "string";

export type Predicate =
  | {
      claim: string;
      op: Comparator;
      value: bigint | number | Date | string;
      format?: ClaimFormatHint;
    }
  | {
      claim: string;
      op: Comparator;
      compareTo: { claim: string };
      format?: ClaimFormatHint;
    };

export type PredicateExpression =
  | Predicate
  | { all: PredicateExpression[] }
  | { any: PredicateExpression[] }
  | { not: PredicateExpression };

export interface CompiledPredicates {
  predicates: PredicateSpec[];
  logicExpression: Array<{ type: number; value: number }>;
  decodeFlags: number[];
  claimFormats: number[];
  claimNameToIndex: Map<string, number>;
  birthdayClaimIndex: number | null;
}

const OP_MAP: Record<Comparator, number> = {
  "<=": PredicateOp.LE,
  ">=": PredicateOp.GE,
  "==": PredicateOp.EQ,
};

function isPredicate(node: PredicateExpression): node is Predicate {
  return typeof node === "object" && node !== null && "claim" in node && "op" in node;
}

function isClaimNameLikelyDate(name: string): boolean {
  return /(birth|dob|date|_at$)/i.test(name);
}

function isYymmddString(s: string): boolean {
  // accept "YYMMDD" (6) or "0YYMMDD" (7) shaped numeric strings
  return /^\d{6,7}$/.test(s);
}

function dateToRocBigInt(d: Date): bigint {
  // Taiwan ROC year = Gregorian year - 1911. Encoded as YYMMDD with optional
  // leading zero for ROC years < 100. The dummy-credential fixture uses
  // "0900101" → ROC year 90 (= 2001 AD) Jan 1.
  const yyyy = d.getUTCFullYear();
  const mm = d.getUTCMonth() + 1;
  const dd = d.getUTCDate();
  const rocYear = yyyy - 1911;
  if (rocYear < 1 || rocYear > 999) {
    throw new InputError(
      "PARAMS_EXCEEDED",
      `Date ${d.toISOString()} out of ROC range (year 1912..2910)`,
    );
  }
  return BigInt(rocYear * 10000 + mm * 100 + dd);
}

function inferFormat(p: Predicate, claimName: string): ClaimFormatHint {
  if (p.format) return p.format;
  if ("value" in p) {
    const v = p.value;
    if (v instanceof Date) return "date";
    if (typeof v === "bigint" || typeof v === "number") {
      return isClaimNameLikelyDate(claimName) ? "date" : "uint";
    }
    if (typeof v === "string") {
      if (isClaimNameLikelyDate(claimName) && isYymmddString(v)) return "date";
      return "string";
    }
  }
  // claim-to-claim comparison with no hint: pick uint and let the other
  // side reconcile through inferred-once-then-frozen logic below.
  return isClaimNameLikelyDate(claimName) ? "date" : "uint";
}

const ALL_OPS: readonly number[] = [PredicateOp.LE, PredicateOp.GE, PredicateOp.EQ];

// Which operators each circuit format code may be compared with. Ordering is
// only defined over numeric encodings; strings and bools are packed into an
// integer, so LE/GE over them would order an arbitrary byte packing.
const ALLOWED_OPS_BY_FORMAT_CODE: Record<number, readonly number[]> = {
  0: [PredicateOp.EQ],
  1: ALL_OPS,
  2: ALL_OPS,
  3: ALL_OPS,
  4: [PredicateOp.EQ],
};

const OP_NAMES: Record<number, string> = {
  [PredicateOp.LE]: "<=",
  [PredicateOp.GE]: ">=",
  [PredicateOp.EQ]: "==",
};

function opFormatError(op: number, formatCode: number): string | null {
  const allowed = ALLOWED_OPS_BY_FORMAT_CODE[formatCode];
  if (allowed?.includes(op)) return null;
  return `Operator ${OP_NAMES[op] ?? `code ${op}`} is not allowed over ${
    FORMAT_CODE_NAMES[formatCode] ?? `format ${formatCode}`
  } claims`;
}

function formatToCircuitCodes(f: ClaimFormatHint): { decodeFlag: number; claimFormat: number } {
  switch (f) {
    case "date":
      return { decodeFlag: 1, claimFormat: 3 };
    case "uint":
      return { decodeFlag: 1, claimFormat: 1 };
    case "string":
      return { decodeFlag: 1, claimFormat: 4 };
  }
}

// EvalPredicate compares over [0, 2^VALUE_BITS) and the circuits are
// instantiated with valueBits = 64. A literal outside that domain cannot be
// compared soundly, so reject it here instead of producing an unsatisfiable
// witness later.
const VALUE_DOMAIN_MAX = 1n << 64n;

function normalizeLiteralValue(
  v: bigint | number | Date | string,
  format: ClaimFormatHint,
): bigint {
  const out = normalizeLiteralValueUnchecked(v, format);
  if (out < 0n || out >= VALUE_DOMAIN_MAX) {
    throw new InputError(
      "INVALID_KEY",
      `Predicate value ${out} is outside the comparable range [0, 2^64)`,
    );
  }
  return out;
}

function normalizeLiteralValueUnchecked(
  v: bigint | number | Date | string,
  format: ClaimFormatHint,
): bigint {
  if (v instanceof Date) {
    if (format !== "date") {
      throw new InputError(
        "INVALID_KEY",
        `Date value supplied for ${format} predicate; declare format: "date" or use a numeric value`,
      );
    }
    return dateToRocBigInt(v);
  }
  if (typeof v === "bigint") return v;
  if (typeof v === "number") {
    // Above 2^53 - 1 a JS number has already been rounded by the time it gets
    // here, so BigInt(v) would silently compile a different constant.
    if (!Number.isSafeInteger(v)) {
      throw new InputError(
        "INVALID_KEY",
        `Predicate value ${v} is not a safe integer; pass a bigint or a decimal string to keep full precision`,
      );
    }
    return BigInt(v);
  }
  if (typeof v === "string") {
    if (format === "date" && isYymmddString(v)) return BigInt(v);
    if (format === "uint" && /^-?\d+$/.test(v)) return BigInt(v);
    throw new InputError(
      "INVALID_KEY",
      `String value "${v}" cannot be normalized for format ${format}`,
    );
  }
  throw new InputError("INVALID_KEY", `Unsupported predicate value type: ${typeof v}`);
}

/**
 * Compile a typed PredicateExpression into the circuit-level inputs.
 *
 * Walks the expression in postfix order to produce the RPN `logicExpression`
 * and a flat `predicates[]` indexed in DFS order. Format inference happens
 * the first time a claim is referenced; subsequent references must agree.
 */
export function compilePredicateExpression(
  expr: PredicateExpression,
  claims: DisclosedClaim[],
): CompiledPredicates {
  const claimNameToIndex = new Map<string, number>();
  for (const c of claims) claimNameToIndex.set(c.name, c.index);

  const claimFormatChosen = new Map<number, ClaimFormatHint>();

  function lookupClaim(name: string): number {
    const idx = claimNameToIndex.get(name);
    if (idx === undefined) {
      throw new InputError(
        "CLAIM_NOT_FOUND",
        `Predicate references unknown claim "${name}". Known claims: ${
          claims.map((c) => c.name).join(", ") || "(none)"
        }`,
      );
    }
    return idx;
  }

  function recordFormat(claimIndex: number, claimName: string, format: ClaimFormatHint) {
    const prior = claimFormatChosen.get(claimIndex);
    if (prior && prior !== format) {
      throw new InputError(
        "PARAMS_EXCEEDED",
        `Claim "${claimName}" referenced with conflicting formats: "${prior}" vs "${format}"`,
      );
    }
    claimFormatChosen.set(claimIndex, format);
  }

  const compiledPredicates: PredicateSpec[] = [];
  const logicExpression: Array<{ type: number; value: number }> = [];

  function compileLeaf(p: Predicate): number {
    const claimIdx = lookupClaim(p.claim);
    const format = inferFormat(p, p.claim);
    recordFormat(claimIdx, p.claim, format);
    const formatError = opFormatError(OP_MAP[p.op], formatToCircuitCodes(format).claimFormat);
    if (formatError) throw new InputError("CLAIM_FORMAT_MISMATCH", `${formatError} (claim "${p.claim}")`);

    if ("compareTo" in p) {
      const rhsIdx = lookupClaim(p.compareTo.claim);
      recordFormat(rhsIdx, p.compareTo.claim, format);
      compiledPredicates.push({
        claimRef: claimIdx,
        claimName: p.claim,
        op: OP_MAP[p.op],
        rhs: { kind: "claimRef", index: rhsIdx, name: p.compareTo.claim },
      });
    } else {
      compiledPredicates.push({
        claimRef: claimIdx,
        claimName: p.claim,
        op: OP_MAP[p.op],
        rhs: { kind: "literal", value: normalizeLiteralValue(p.value, format) },
      });
    }
    return compiledPredicates.length - 1;
  }

  function walk(node: PredicateExpression): void {
    if (isPredicate(node)) {
      const idx = compileLeaf(node);
      logicExpression.push({ type: LogicToken.REF, value: idx });
      return;
    }
    if ("all" in node) {
      if (node.all.length === 0) {
        throw new InputError("PARAMS_EXCEEDED", "`all` expression must contain at least one predicate");
      }
      walk(node.all[0]!);
      for (let i = 1; i < node.all.length; i++) {
        walk(node.all[i]!);
        logicExpression.push({ type: LogicToken.AND, value: 0 });
      }
      return;
    }
    if ("any" in node) {
      if (node.any.length === 0) {
        throw new InputError("PARAMS_EXCEEDED", "`any` expression must contain at least one predicate");
      }
      walk(node.any[0]!);
      for (let i = 1; i < node.any.length; i++) {
        walk(node.any[i]!);
        logicExpression.push({ type: LogicToken.OR, value: 0 });
      }
      return;
    }
    if ("not" in node) {
      walk(node.not);
      logicExpression.push({ type: LogicToken.NOT, value: 0 });
      return;
    }
    throw new InputError("PARAMS_EXCEEDED", `Unknown predicate expression node: ${JSON.stringify(node)}`);
  }

  walk(expr);

  // Sized by the highest slot a predicate reads, not claims.length: a sparse
  // schema's referenced index can exceed its claim count, and the verifier
  // fails closed on any referenced slot these arrays do not cover.
  const decodeFlags: number[] = [];
  const claimFormats: number[] = [];
  // Unreachable through the DSL (every leaf references a claim and empty
  // all/any throw), but Math.max() of nothing is -Infinity and would silently
  // yield zero slots.
  if (claimFormatChosen.size === 0) {
    throw new InputError("PARAMS_EXCEEDED", "Policy does not read any claim");
  }
  const slotCount = Math.max(...claimFormatChosen.keys()) + 1;
  for (let i = 0; i < slotCount; i++) {
    const chosen = claimFormatChosen.get(i);
    const { decodeFlag, claimFormat } = formatToCircuitCodes(chosen ?? "uint");
    // Decode only claims referenced by a predicate; unreferenced slots stay
    // undecoded to save constraints.
    decodeFlags.push(chosen ? decodeFlag : 0);
    claimFormats.push(claimFormat);
  }

  // Identify a "birthday-like" claim index (first claim compiled with "date"
  // format) so the legacy precompute path can still default decodeFlags
  // around it. Pure heuristic, not consumed by the new path.
  let birthdayClaimIndex: number | null = null;
  for (const [idx, format] of claimFormatChosen) {
    if (format === "date") {
      birthdayClaimIndex = idx;
      break;
    }
  }

  return {
    predicates: compiledPredicates,
    logicExpression,
    decodeFlags,
    claimFormats,
    claimNameToIndex,
    birthdayClaimIndex,
  };
}

const FORMAT_CODE_NAMES: Record<number, string> = {
  0: "bool",
  1: "uint",
  2: "iso_date",
  3: "roc_date",
  4: "string",
};

/** The normalization a compiled predicate program requires of the claims it reads. */
export function requiredNormalization(compiled: CompiledPredicates): ClaimNormalization {
  return {
    decodeFlags: compiled.decodeFlags,
    claimFormats: compiled.claimFormats,
  };
}

/** Reverse the compiled name-to-index map, for error messages. */
export function claimNamesByIndex(compiled: CompiledPredicates): Map<number, string> {
  const names = new Map<number, string>();
  for (const [name, index] of compiled.claimNameToIndex) {
    names.set(index, name);
  }
  return names;
}

/**
 * Check that every slot the predicates read is expected to be decoded and has
 * an expected format, and that each operator is allowed over that format. This
 * is the verifier's own copy of the compiler's table, applied to the
 * expectation it was handed, so a hand-built or tampered `ExpectedStatement`
 * cannot carry a combination the compiler rejects.
 *
 * @returns an error message, or null when the predicates are well-formed.
 */
export function checkPredicateFormats(
  predicates: PredicateSpec[],
  normalization: ClaimNormalization,
): string | null {
  const slotError = (slot: number, name: string, op: number): string | null => {
    // checkNormalizationSupports only compares slots the expectation marks as
    // decoded, so an undecoded read slot would never have its format checked.
    if (normalization.decodeFlags[slot] !== 1) {
      return `Policy reads claim "${name}" (slot ${slot}), but the expected normalization leaves it undecoded`;
    }
    const code = normalization.claimFormats[slot];
    if (code === undefined) {
      return `Policy reads claim "${name}" (slot ${slot}), but the expected normalization has no expected format for that slot`;
    }
    const err = opFormatError(op, code);
    return err ? `${err} (claim "${name}")` : null;
  };
  for (const spec of predicates) {
    const lhs = slotError(spec.claimRef, spec.claimName, spec.op);
    if (lhs) return lhs;
    if (spec.rhs.kind === "claimRef") {
      const rhs = slotError(spec.rhs.index, spec.rhs.name, spec.op);
      if (rhs) return rhs;
      const lhsCode = normalization.claimFormats[spec.claimRef];
      const rhsCode = normalization.claimFormats[spec.rhs.index];
      if (lhsCode !== rhsCode) {
        const name = (c: number | undefined) =>
          c === undefined ? "none" : (FORMAT_CODE_NAMES[c] ?? `format ${c}`);
        return `Claim "${spec.claimName}" and "${spec.rhs.name}" compared with conflicting formats: "${name(lhsCode)}" vs "${name(rhsCode)}"`;
      }
    }
  }
  return null;
}

/**
 * Check that claim values normalized as `actual` can answer predicates that
 * require `required`.
 *
 * A normalized claim value only answers a predicate if the JWT circuit decoded
 * that claim slot and normalized it under the format the predicate compares
 * against:
 *
 *   - a slot with decodeFlag 0 holds 0, not the claim's value, so any
 *     comparison against it is a comparison against 0
 *   - a slot normalized as "uint" holds a decimal integer, which is not
 *     comparable to a "date" literal, and so on for every other pairing
 *
 * Only the slots `required` marks as read are checked. Slots no predicate
 * refers to never reach a comparison, so a credential prepared for a wider set
 * of predicates than this one still passes.
 *
 * @returns an error message, or null when `actual` answers `required`.
 */
export function checkNormalizationSupports(
  actual: ClaimNormalization,
  required: ClaimNormalization,
  claimNames?: Map<number, string>,
): string | null {
  const describe = (i: number) => claimNames?.get(i) ?? `claim slot ${i}`;
  const formatName = (code: number | undefined) =>
    code === undefined ? "none" : (FORMAT_CODE_NAMES[code] ?? `format ${code}`);

  for (let i = 0; i < required.decodeFlags.length; i++) {
    if (required.decodeFlags[i] !== 1) continue;

    if (actual.decodeFlags[i] !== 1) {
      return (
        `Predicate reads ${describe(i)}, but that claim was left undecoded, so its ` +
        `normalized value is 0 rather than the credential's value.`
      );
    }

    if (actual.claimFormats[i] !== required.claimFormats[i]) {
      return (
        `Predicate reads ${describe(i)} as ${formatName(required.claimFormats[i])}, ` +
        `but it was normalized as ${formatName(actual.claimFormats[i])}.`
      );
    }
  }

  return null;
}

/**
 * Throwing form of [`checkNormalizationSupports`], for the proving side.
 *
 * @throws InputError CLAIM_FORMAT_MISMATCH if a slot a predicate reads was left
 *         undecoded or was normalized under a different format.
 */
export function assertNormalizationSupports(
  normalization: ClaimNormalization,
  compiled: CompiledPredicates,
): void {
  const message = checkNormalizationSupports(
    normalization,
    requiredNormalization(compiled),
    claimNamesByIndex(compiled),
  );
  if (message) {
    throw new InputError(
      "CLAIM_FORMAT_MISMATCH",
      `${message} Precompute again with predicates that cover every claim this ` +
        `presentation reads, in the formats it compares against.`,
    );
  }
}
