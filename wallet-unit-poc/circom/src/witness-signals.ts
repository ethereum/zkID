import { createReadStream } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline";
import type { WitnessTester } from "circomkit";

/**
 * Witness indices of the named symbols (e.g. `main.deviceKeyX`), read from the
 * `.sym` of the circuit `tester` compiled.
 *
 * Not from `build/<circuit>/`: WitnessTester compiles its own main at O1 with no
 * public list, so private signals sit at different indices than in compile.sh's
 * O2 build, and an offset taken from one is wrong in the other. circomkit's
 * `readWitness()` is unusable here too, since it reads the whole `.sym` into a
 * string and mdoc's is ~1.1 GB, past Node's max string length.
 */
export async function witnessIndices(
  tester: WitnessTester<any, any>,
  symbols: string[],
): Promise<number[]> {
  // circomkit-internal, but the only handle on the dir the tester compiled into.
  const circomTester = (tester as any).circomTester;
  const symPath = join(circomTester.dir, `${circomTester.baseName}.sym`);

  const pending = new Map(symbols.map((s, i) => [s, i]));
  const indices = new Array<number>(symbols.length).fill(-1);

  const lines = createInterface({ input: createReadStream(symPath), crlfDelay: Infinity });
  try {
    for await (const line of lines) {
      // `labelIdx,witnessIdx,componentIdx,symbolName`; witnessIdx -1 = optimized away.
      const [, witnessIdx, , name] = line.split(",");
      const slot = pending.get(name);
      if (slot === undefined) continue;
      if (Number(witnessIdx) < 0) throw new Error(`${name} was optimized out`);
      indices[slot] = Number(witnessIdx);
      pending.delete(name);
      if (pending.size === 0) break;
    }
  } finally {
    lines.close();
  }

  if (pending.size > 0) {
    throw new Error(`not found in ${symPath}: ${[...pending.keys()].join(", ")}`);
  }
  return indices;
}
