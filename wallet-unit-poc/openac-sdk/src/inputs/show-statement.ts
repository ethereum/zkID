// Canonical construction of the Show circuit's verifier statement: the public
// data that binds a presentation to a specific nonce/challenge and predicate
// policy. This is the SINGLE source of truth shared by the prover (which feeds
// these values into the witness) and the verifier (which recomputes them from
// its expected nonce + policy and compares against the proof's public IO).
//
// The Show circuit exposes its public signals as the contiguous witness prefix
// `witness[1..=num_public]`, in this order (see circom/circuits/main/show.circom):
//   [0] expressionResult   (output; NOT produced here, it is the result bit)
//   [1..3] issuerRoot      (output, [hi, lo]; NOT produced here)
//   [3..5] revocationRoot  (output, [hi, lo]; NOT produced here)
//   [5] messageHash
//   [6] predicateLen
//   [7..]  predicateClaimRefs[maxPredicates]
//          predicateOps[maxPredicates]
//          predicateRhsIsRef[maxPredicates]
//          predicateRhsValues[maxPredicates]
//          predicateClaimIdentifiers[maxPredicates]
//          tokenTypes[maxLogicTokens]
//          tokenValues[maxLogicTokens]
//          exprLen
//
// The order is the input DECLARATION order in circuits/show.circom, not the
// order of the `public[...]` list in the generated main component -- circom
// assigns public positions by declaration. `predicateClaimIdentifiers` is
// declared between predicateRhsValues and tokenTypes, so it flattens there.
//
// `buildShowStatementFields` returns the padded arrays; `buildShowStatementPublicValues`
// flattens them (excluding the outputs) into the exact order above.

import { sha256 } from "@noble/hashes/sha2";
import { bytesToBigInt, P256_SCALAR_ORDER } from "../utils.js";
import { InputError } from "../errors.js";
import { PredicateOp } from "./show-input-builder.js";
import type { PredicateSpec } from "./show-input-builder.js";
import type { ShowCircuitParams } from "../types.js";

/** Fixed byte width the circuit hashes an attribute name over (jwt.circom NAME_ID_LEN). */
export const NAME_ID_LEN = 31;

/** UTF-8 encode a claim name into a fixed NAME_ID_LEN byte buffer + length. */
export function nameToBuffer(name: string): { bytes: bigint[]; len: bigint } {
  const raw = Array.from(new TextEncoder().encode(name));
  if (raw.length > NAME_ID_LEN) {
    throw new InputError(
      "PARAMS_EXCEEDED",
      `Claim name "${name}" is ${raw.length} bytes; max ${NAME_ID_LEN}`,
    );
  }
  const bytes = raw.map((b) => BigInt(b));
  while (bytes.length < NAME_ID_LEN) bytes.push(0n);
  return { bytes, len: BigInt(raw.length) };
}

export interface ShowStatementFields {
  /** Scalar-field-reduced hash of the verifier nonce. */
  messageHash: bigint;
  predicateLen: bigint;
  predicateClaimRefs: bigint[];
  predicateOps: bigint[];
  predicateRhsIsRef: bigint[];
  predicateRhsValues: bigint[];
  /** LHS attribute name bytes per predicate (the circuit hashes these). */
  predicateClaimNames: bigint[][];
  predicateClaimNameLens: bigint[];
  /** RHS attribute name bytes per predicate (claim-to-claim compareTo only). */
  predicateRhsClaimNames: bigint[][];
  predicateRhsClaimNameLens: bigint[];
  tokenTypes: bigint[];
  tokenValues: bigint[];
  exprLen: bigint;
}

/** Minimum verifier-nonce length. Below this an attacker could precompute the
 *  messageHash offline, and `undefined`/"" both collapse to the same constant. */
export const MIN_NONCE_LENGTH = 16;

/** Reduce sha256(nonce) into the P-256 scalar field, matching the Show circuit's messageHash. */
export function computeMessageHash(nonce: string): bigint {
  if (typeof nonce !== "string" || nonce.length < MIN_NONCE_LENGTH) {
    throw new InputError(
      "INVALID_NONCE",
      `nonce must be a string of at least ${MIN_NONCE_LENGTH} characters`,
    );
  }
  const digest = sha256(new TextEncoder().encode(nonce));
  return bytesToBigInt(digest) % P256_SCALAR_ORDER;
}

/**
 * Build the padded predicate/token arrays and message hash exactly as the Show
 * witness does. The padding conventions here MUST match the circuit witness:
 * unused predicateOps slots default to EQ, everything else defaults to 0.
 */
export function buildShowStatementFields(
  params: ShowCircuitParams,
  nonce: string,
  predicates: PredicateSpec[],
  logicExpression: Array<{ type: number; value: number }>,
): ShowStatementFields {
  if (predicates.length > params.maxPredicates) {
    throw new InputError(
      "PARAMS_EXCEEDED",
      `Predicate count (${predicates.length}) exceeds maxPredicates (${params.maxPredicates})`,
    );
  }
  if (logicExpression.length > params.maxLogicTokens) {
    throw new InputError(
      "PARAMS_EXCEEDED",
      `Logic expression length (${logicExpression.length}) exceeds maxLogicTokens (${params.maxLogicTokens})`,
    );
  }

  const predicateClaimRefs: bigint[] = Array(params.maxPredicates).fill(0n);
  const predicateOps: bigint[] = Array(params.maxPredicates).fill(BigInt(PredicateOp.EQ));
  const predicateRhsIsRef: bigint[] = Array(params.maxPredicates).fill(0n);
  const predicateRhsValues: bigint[] = Array(params.maxPredicates).fill(0n);
  // The verifier names the attribute each operand must be; the Show circuit
  // hashes these to the identity it enforces (Items 1+3). Unused slots stay
  // zero-length (hash of an empty name), never matched by an active predicate.
  const emptyName = (): bigint[] => Array(NAME_ID_LEN).fill(0n);
  const predicateClaimNames: bigint[][] = Array.from({ length: params.maxPredicates }, emptyName);
  const predicateClaimNameLens: bigint[] = Array(params.maxPredicates).fill(0n);
  const predicateRhsClaimNames: bigint[][] = Array.from({ length: params.maxPredicates }, emptyName);
  const predicateRhsClaimNameLens: bigint[] = Array(params.maxPredicates).fill(0n);

  for (let i = 0; i < predicates.length; i++) {
    const spec = predicates[i]!;
    predicateClaimRefs[i] = BigInt(spec.claimRef);
    predicateOps[i] = BigInt(spec.op);

    const lhs = nameToBuffer(spec.claimName);
    predicateClaimNames[i] = lhs.bytes;
    predicateClaimNameLens[i] = lhs.len;

    if (spec.rhs.kind === "literal") {
      predicateRhsIsRef[i] = 0n;
      predicateRhsValues[i] = spec.rhs.value;
    } else {
      predicateRhsIsRef[i] = 1n;
      predicateRhsValues[i] = BigInt(spec.rhs.index);
      const rhs = nameToBuffer(spec.rhs.name);
      predicateRhsClaimNames[i] = rhs.bytes;
      predicateRhsClaimNameLens[i] = rhs.len;
    }
  }

  const tokenTypes: bigint[] = Array(params.maxLogicTokens).fill(0n);
  const tokenValues: bigint[] = Array(params.maxLogicTokens).fill(0n);
  for (let i = 0; i < logicExpression.length; i++) {
    tokenTypes[i] = BigInt(logicExpression[i]!.type);
    tokenValues[i] = BigInt(logicExpression[i]!.value);
  }

  return {
    messageHash: computeMessageHash(nonce),
    predicateLen: BigInt(predicates.length),
    predicateClaimRefs,
    predicateOps,
    predicateRhsIsRef,
    predicateRhsValues,
    predicateClaimNames,
    predicateClaimNameLens,
    predicateRhsClaimNames,
    predicateRhsClaimNameLens,
    tokenTypes,
    tokenValues,
    exprLen: BigInt(logicExpression.length),
  };
}

/**
 * Public outputs before the statement: expressionResult and issuerRoot[2], plus
 * revocationRoot[2] with revocation.
 */
export function showNumOutputs(params: ShowCircuitParams): number {
  return params.revocationMaxDepth > 0 ? 5 : 3;
}

/**
 * Flatten the statement fields into the public-value vector in circuit order,
 * EXCLUDING the leading outputs (`showNumOutputs`).
 */
export function buildShowStatementPublicValues(
  params: ShowCircuitParams,
  nonce: string,
  predicates: PredicateSpec[],
  logicExpression: Array<{ type: number; value: number }>,
): bigint[] {
  const f = buildShowStatementFields(params, nonce, predicates, logicExpression);
  return [
    f.messageHash,
    f.predicateLen,
    ...f.predicateClaimRefs,
    ...f.predicateOps,
    ...f.predicateRhsIsRef,
    ...f.predicateRhsValues,
    ...f.predicateClaimNames.flat(),
    ...f.predicateClaimNameLens,
    ...f.predicateRhsClaimNames.flat(),
    ...f.predicateRhsClaimNameLens,
    ...f.tokenTypes,
    ...f.tokenValues,
    f.exprLen,
  ];
}
