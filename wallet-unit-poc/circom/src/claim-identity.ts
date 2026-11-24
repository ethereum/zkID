import type { WitnessTester } from "circomkit";
import { circomkit } from "./circomkit.ts";
import { nameToBuffer, NAME_ID_LEN } from "./show.ts";

// No JS Poseidon runs over secq256r1, so the hasher circuit computes H(name).
let hasher: Promise<WitnessTester<any, any>> | undefined;
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
  const { "main.hash": value } = await h.readWitness(w, ["main.hash"]);
  hashes.set(name, value);
  return value;
}

/** Sets predicate `pred`'s claim name and slot `slot`'s identity to `name`. */
export async function bindPredicateName(inputs: any, pred: number, slot: number, name: string): Promise<void> {
  const { bytes, len } = nameToBuffer(name);
  inputs.predicateClaimNames[pred] = bytes;
  inputs.predicateClaimNameLens[pred] = len;
  inputs.claimIdentifierHashes[slot] = await hashClaimName(name);
}

/** Same as bindPredicateName, for the predicate's RHS claim. */
export async function bindPredicateRhsName(inputs: any, pred: number, slot: number, name: string): Promise<void> {
  const { bytes, len } = nameToBuffer(name);
  inputs.predicateRhsClaimNames[pred] = bytes;
  inputs.predicateRhsClaimNameLens[pred] = len;
  inputs.claimIdentifierHashes[slot] = await hashClaimName(name);
}
