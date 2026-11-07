import type { WitnessTester } from "circomkit";
import { circomkit } from "./index.ts";
import { witnessValues } from "./witness-signals.ts";
import { nameToBuffer, NAME_ID_LEN } from "../../src/show.ts";

// H(name) as the credential/Show circuits compute it: HashBytesToFieldWithLen
// over the fixed 31-byte width. The circuits run over secq256r1, so no JS
// Poseidon matches — run the hasher circuit itself and cache the results.
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
  const [value] = await witnessValues(h, w, ["main.hash"]);
  hashes.set(name, value);
  return value;
}

/**
 * Bind predicate `pred`'s LHS to claim slot `slot` under attribute `name`:
 * sets the verifier-side name bytes and the matching slot identity, which the
 * post-audit Show circuit requires for every active predicate.
 */
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
