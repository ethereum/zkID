import { Circomkit } from "circomkit";
import type { WitnessTester } from "circomkit";

import { witnessIndices } from "./witness-signals.ts";
import { nameToBuffer, NAME_ID_LEN } from "./show.ts";

// Matches tests/common/index.ts; duplicated so src does not import the test tree.
const circomkit = new Circomkit({
  verbose: false,
  prime: "secq256r1",
  optimization: 2,
});

// The circuits hash over secq256r1, which no JS Poseidon matches, so run the
// hasher circuit itself and cache what it returns.
let hasher: Promise<WitnessTester<any, any>> | undefined;
let hashIdx: number | undefined;
const hashes = new Map<string, bigint>();

export async function hashClaimName(name: string): Promise<bigint> {
  const cached = hashes.get(name);
  if (cached !== undefined) return cached;
  hasher ??= circomkit.WitnessTester("ClaimNameHash31", {
    file: "keyless_zk_proofs/hashtofield",
    template: "HashBytesToFieldWithLen",
    params: [NAME_ID_LEN],
    recompile: true,
  });
  const h = await hasher;
  const { bytes, len } = nameToBuffer(name);
  const w = await h.calculateWitness({ in: bytes, len });
  hashIdx ??= (await witnessIndices(h, ["main.hash"]))[0];
  const value = w[hashIdx];
  hashes.set(name, value);
  return value;
}

/** Bind predicate `pred` to claim slot `slot` under `name`. Show requires both. */
export async function bindPredicateName(inputs: any, pred: number, slot: number, name: string): Promise<void> {
  const { bytes, len } = nameToBuffer(name);
  inputs.predicateClaimNames[pred] = bytes;
  inputs.predicateClaimNameLens[pred] = len;
  inputs.claimIdentifierHashes[slot] = await hashClaimName(name);
}

/** Same as bindPredicateName, for a claim-to-claim predicate's RHS slot. */
export async function bindPredicateRhsName(inputs: any, pred: number, slot: number, name: string): Promise<void> {
  const { bytes, len } = nameToBuffer(name);
  inputs.predicateRhsClaimNames[pred] = bytes;
  inputs.predicateRhsClaimNameLens[pred] = len;
  inputs.claimIdentifierHashes[slot] = await hashClaimName(name);
}
