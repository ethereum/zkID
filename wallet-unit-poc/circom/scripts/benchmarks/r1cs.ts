import * as fs from "fs";

export interface R1csInfo {
  prime: bigint;
  wires: number;
  outputs: number;
  publicInputs: number;
  privateInputs: number;
  labels: number;
  constraints: number;
  nnzA: number;
  nnzB: number;
  nnzC: number;
}

const readLE = (buf: Buffer, off: number, n: number): bigint => {
  let v = 0n;
  for (let i = n - 1; i >= 0; i--) v = (v << 8n) | BigInt(buf[off + i]);
  return v;
};

function sections(buf: Buffer, magic: string): Map<number, [number, number]> {
  if (buf.toString("latin1", 0, 4) !== magic) throw new Error(`not a ${magic} file`);
  const n = buf.readUInt32LE(8);
  const out = new Map<number, [number, number]>();
  let off = 12;
  for (let i = 0; i < n; i++) {
    const type = buf.readUInt32LE(off);
    const size = Number(buf.readBigUInt64LE(off + 4));
    out.set(type, [off + 12, size]);
    off += 12 + size;
  }
  return out;
}

/** Reads the r1cs header and counts constraint terms; with `witness`, also checks A*B=C on every constraint. */
export function readR1cs(r1csPath: string, witnessPath?: string): R1csInfo & { satisfied?: boolean; firstFailure?: number } {
  const buf = fs.readFileSync(r1csPath);
  const secs = sections(buf, "r1cs");
  const [h] = secs.get(1)!;
  const n8 = buf.readUInt32LE(h);
  const prime = readLE(buf, h + 4, n8);
  let o = h + 4 + n8;
  const wires = buf.readUInt32LE(o);
  const info: R1csInfo = {
    prime,
    wires,
    outputs: buf.readUInt32LE(o + 4),
    publicInputs: buf.readUInt32LE(o + 8),
    privateInputs: buf.readUInt32LE(o + 12),
    labels: Number(buf.readBigUInt64LE(o + 16)),
    constraints: buf.readUInt32LE(o + 24),
    nnzA: 0,
    nnzB: 0,
    nnzC: 0,
  };

  let w: bigint[] | undefined;
  if (witnessPath) {
    const wb = fs.readFileSync(witnessPath);
    const ws = sections(wb, "wtns");
    const [w1] = ws.get(1)!;
    const wn8 = wb.readUInt32LE(w1);
    if (readLE(wb, w1 + 4, wn8) !== prime) throw new Error("witness prime differs from r1cs prime");
    const count = wb.readUInt32LE(w1 + 4 + wn8);
    if (count !== wires) throw new Error(`witness has ${count} values, r1cs has ${wires} wires`);
    const [w2] = ws.get(2)!;
    w = Array.from({ length: count }, (_, i) => readLE(wb, w2 + i * wn8, wn8));
    if (w[0] !== 1n) throw new Error(`witness[0] is ${w[0]}, expected the constant 1`);
  }

  const [c0] = secs.get(2)!;
  o = c0;
  let firstFailure: number | undefined;
  for (let c = 0; c < info.constraints; c++) {
    const vals: bigint[] = [];
    for (const key of ["nnzA", "nnzB", "nnzC"] as const) {
      const nt = buf.readUInt32LE(o);
      o += 4;
      info[key] += nt;
      let acc = 0n;
      for (let t = 0; t < nt; t++) {
        if (w) acc += readLE(buf, o + 4, n8) * w[buf.readUInt32LE(o)];
        o += 4 + n8;
      }
      vals.push(acc);
    }
    if (w && firstFailure === undefined && (vals[0] % prime) * (vals[1] % prime) % prime !== vals[2] % prime) firstFailure = c;
  }
  return w ? { ...info, satisfied: firstFailure === undefined, firstFailure } : info;
}
