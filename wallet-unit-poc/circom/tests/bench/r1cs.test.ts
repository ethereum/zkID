import assert from "assert";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { readR1cs } from "../../scripts/benchmarks/r1cs.ts";

const P = 101n;
const u32 = (n: number) => Buffer.from(new Uint32Array([n]).buffer);
const u64 = (n: number) => Buffer.from(new BigUint64Array([BigInt(n)]).buffer);
const fe = (v: bigint) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(v);
  return b;
};
const section = (type: number, body: Buffer) => Buffer.concat([u32(type), u64(body.length), body]);
const lcBytes = (terms: [number, bigint][]) => Buffer.concat([u32(terms.length), ...terms.flatMap(([i, c]) => [u32(i), fe(c)])]);

// One constraint, w1 * w2 = w3, over 4 wires (wire 0 is the constant 1).
function write(dir: string, witness: bigint[]): [string, string] {
  const header = Buffer.concat([u32(8), fe(P), u32(4), u32(0), u32(2), u32(1), u64(4), u32(1)]);
  const cons = Buffer.concat([lcBytes([[1, 1n]]), lcBytes([[2, 1n]]), lcBytes([[3, 1n]])]);
  const r1cs = Buffer.concat([Buffer.from("r1cs"), u32(1), u32(2), section(1, header), section(2, cons)]);
  const wh = Buffer.concat([u32(8), fe(P), u32(witness.length)]);
  const wtns = Buffer.concat([Buffer.from("wtns"), u32(2), u32(2), section(1, wh), section(2, Buffer.concat(witness.map(fe)))]);
  const r = path.join(dir, "t.r1cs");
  const w = path.join(dir, "t.wtns");
  fs.writeFileSync(r, r1cs);
  fs.writeFileSync(w, wtns);
  return [r, w];
}

describe("readR1cs", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "r1cs-test-"));
  after(() => fs.rmSync(dir, { recursive: true, force: true }));

  it("reads header counts and term counts", () => {
    const [r] = write(dir, [1n, 3n, 4n, 12n]);
    const info = readR1cs(r);
    assert.strictEqual(info.constraints, 1);
    assert.strictEqual(info.wires, 4);
    assert.strictEqual(info.publicInputs, 2);
    assert.strictEqual(info.nnzA + info.nnzB + info.nnzC, 3);
  });

  it("accepts a satisfying witness and rejects a wrong one", () => {
    const [r, w] = write(dir, [1n, 3n, 4n, 12n]);
    assert.strictEqual(readR1cs(r, w).satisfied, true);
    const [r2, w2] = write(dir, [1n, 3n, 4n, 13n]);
    const bad = readR1cs(r2, w2);
    assert.strictEqual(bad.satisfied, false);
    assert.strictEqual(bad.firstFailure, 0);
  });

  it("fails loudly when witness[0] is not 1", () => {
    const [r, w] = write(dir, [2n, 3n, 4n, 12n]);
    assert.throws(() => readR1cs(r, w), /witness\[0\]/);
  });
});
