import type { WitnessTester } from "circomkit";

/**
 * Values in `witness` of the given full symbol names (e.g. `main.deviceKeyX`,
 * `main.normalizedClaimValues[0]`), looked up in the `.sym` of the circuit that
 * `tester` actually compiled.
 *
 * Read them through the tester rather than from `build/<circuit>/`:
 * `Circomkit.WitnessTester` compiles its own main (no `public[...]` list) at
 * optimization level 1, while `scripts/compile.sh` builds `circuits/main/` at
 * O2 with the public inputs declared. The two layouts do not match -- a private
 * signal sits at a different index in each -- so an offset taken from one is
 * wrong in the other. (That mismatch is exactly how
 * MDOC_CLAIM_VALUES_WITNESS_START in ecdsa-spartan2 ended up pointing at 3321,
 * a tester-build index, when the production build puts it at 3036.)
 *
 * circomkit streams the `.sym` and stops once every requested symbol is found,
 * so this also works for `.sym` files past Node's ~512 MB max string length
 * (mdoc's is ~1.1 GB). A symbol that was optimized out throws.
 */
export async function witnessValues(
  tester: WitnessTester<any, any>,
  witness: bigint[],
  symbols: string[],
): Promise<bigint[]> {
  const values = await tester.readWitness(witness, symbols);
  return symbols.map((s) => values[s]);
}
