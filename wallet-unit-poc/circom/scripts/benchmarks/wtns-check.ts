import { readR1cs } from "./r1cs.ts";

const [r1cs, wtns] = process.argv.slice(2);
if (!r1cs || !wtns) {
  console.error("usage: tsx scripts/benchmarks/wtns-check.ts <r1cs> <wtns>");
  process.exit(2);
}
const r = readR1cs(r1cs, wtns);
console.log(JSON.stringify({ constraints: r.constraints, satisfied: r.satisfied, firstFailure: r.firstFailure ?? null }));
process.exit(r.satisfied ? 0 : 1);
