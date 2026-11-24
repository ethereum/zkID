/**
 * Compiles the sweep cells in variants.ts and appends one SHAPE row per cell to
 * $OPENACPLUS_BENCH_ROOT/variants/shape.jsonl.
 *
 *   npx tsx scripts/benchmarks/run-sweep.ts [--matrix S-D] [--only name,name] [--jobs 2] [--list] [--force] [--keep-r1cs]
 *   npx tsx scripts/benchmarks/run-sweep.ts --sym-only [--only name,name]   # add <name>.sym beside an existing wasm build
 */
import { spawn, execSync } from "child_process";
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import { benchRoot } from "./provenance.ts";
import { readR1cs } from "./r1cs.ts";
import { allCells, buildDir, mainSource, type Cell } from "./variants.ts";

const circomDir = path.resolve(__dirname, "..", "..");
const outDir = () => path.join(benchRoot(), "variants");
const shapePath = () => path.join(outDir(), "shape.jsonl");
const MAIN_SHA = "9557067";
const repoRoot = path.resolve(circomDir, "..", "..");
const MAIN_FULL = execSync(`git -C ${repoRoot} rev-parse ${MAIN_SHA}`).toString().trim();
const HEAD = execSync(`git -C ${circomDir} rev-parse HEAD`).toString().trim();
const mainSrc = path.join(buildDir, "_main-src");

const args = process.argv.slice(2);
const flag = (n: string) => (args.includes(n) ? args[args.indexOf(n) + 1] : undefined);
const jobs = Number(flag("--jobs") ?? 2);
const force = args.includes("--force");
const keepR1cs = args.includes("--keep-r1cs");

const done = (): Set<string> =>
  new Set(fs.existsSync(shapePath()) ? fs.readFileSync(shapePath(), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l).cell) : []);

function sha256File(p: string): string {
  const h = crypto.createHash("sha256");
  const fd = fs.openSync(p, "r");
  const buf = Buffer.alloc(1 << 24);
  for (let n; (n = fs.readSync(fd, buf, 0, buf.length, null)) > 0; ) h.update(buf.subarray(0, n));
  fs.closeSync(fd);
  return h.digest("hex");
}

/** Main's circuits include "../../node_modules/...", so the scratch copy needs a node_modules beside it. */
function ensureMainSource(): void {
  if (!fs.existsSync(path.join(mainSrc, "circuits", "show.circom"))) {
    fs.mkdirSync(mainSrc, { recursive: true });
    const repo = path.resolve(circomDir, "..", "..");
    execSync(`git -C ${repo} archive ${MAIN_SHA} wallet-unit-poc/circom/circuits | tar -x -C ${mainSrc} --strip-components=2`);
  }
  const link = path.join(mainSrc, "node_modules");
  if (!fs.existsSync(link)) fs.symlinkSync(path.join(circomDir, "node_modules"), link);
}

function compile(c: Cell): Promise<{ r1cs: string; wasm?: string; seconds: number; peakBytes: number | null }> {
  const dir = path.join(buildDir, c.name);
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  const main = path.join(dir, `${c.name}.circom`);
  fs.writeFileSync(main, mainSource(c));
  const lib = c.kind === "show4" ? path.join(mainSrc, "circuits") : path.join(circomDir, "circuits");
  const cargs = [
    main, "--r1cs", "--sym", ...(c.wasm ? ["--wasm"] : []), "-p", "secq256r1", "--O2",
    "-l", lib, "-l", path.join(circomDir, "node_modules"), "-l", path.join(circomDir, "node_modules/circomlib/circuits"), "-o", dir,
  ];
  const circomArgs = cargs;
  const log = fs.openSync(path.join(outDir(), "logs", `${c.name}.log`), "w");
  const t0 = Date.now();
  return new Promise((resolve, reject) => {
    const p = spawn("/usr/bin/time", ["-l", "circom", ...circomArgs], { stdio: ["ignore", log, log] });
    p.on("exit", (code) => {
      fs.closeSync(log);
      if (code !== 0) return reject(new Error(`circom failed for ${c.name}, see logs/${c.name}.log`));
      const text = fs.readFileSync(path.join(outDir(), "logs", `${c.name}.log`), "utf8");
      const m = text.match(/(\d+)\s+peak memory footprint/);
      resolve({
        r1cs: path.join(dir, `${c.name}.r1cs`),
        wasm: c.wasm ? path.join(dir, `${c.name}_js`, `${c.name}.wasm`) : undefined,
        seconds: (Date.now() - t0) / 1000,
        peakBytes: m ? Number(m[1]) : null,
      });
    });
  });
}

function shapeRow(c: Cell, built: { r1cs: string; wasm?: string; seconds: number | null; peakBytes: number | null }) {
  const info = readR1cs(built.r1cs);
  const sp = c.kind === "show" ? c.params : null;
  const jp = c.kind === "jwt" ? c.params : null;
  const bits = (n: number) => Math.ceil(Math.log2(n));
  return {
    kind: "SHAPE",
    cell: c.name,
    matrix_id: c.kind === "sha" ? "X2" : c.matrix,
    path: "generic",
    circuit: c.kind === "jwt" ? "jwt" : c.kind === "sha" ? "sha256" : "show",
    ...(c.kind === "sha" ? { compressions: 1 } : {}),
    config: c.kind === "show4" ? "main" : "variant",
    show_params: sp ?? (c.kind === "show4" ? c.params : null),
    jwt_params: jp,
    n_claims: c.kind === "jwt" ? jp![2] - 2 : c.params[0] ?? null,
    m_pred: c.kind === "show" || c.kind === "show4" ? c.params[1] : null,
    t_tok: c.kind === "show" || c.kind === "show4" ? c.params[2] : null,
    beta: c.kind === "show" || c.kind === "show4" ? c.params[3] : null,
    d_iss: sp ? sp[4] : 0,
    d_rev: sp ? sp[5] : 0,
    constraints: info.constraints,
    wires: info.wires,
    public_inputs: info.publicInputs,
    private_inputs: info.privateInputs,
    outputs: info.outputs,
    labels: info.labels,
    nnz_a: info.nnzA,
    nnz_b: info.nnzB,
    nnz_c: info.nnzC,
    padded_constraints: null,
    padded_vars: null,
    num_shared: null,
    num_precommitted: null,
    num_rest: null,
    // Estimate: Spartan pads to powers of two; the exact sizes come from a key.
    pad_class_log2_constraints: bits(info.constraints),
    pad_class_log2_wires: bits(info.wires),
    r1cs_sha256: sha256File(built.r1cs),
    r1cs_path: built.r1cs,
    wasm_path: built.wasm ?? null,
    compile_s: built.seconds,
    compile_peak_bytes: built.peakBytes,
    command: `npx tsx scripts/benchmarks/run-sweep.ts ${args.join(" ")}`.trim(),
    // The circuit source tree: main's cells come from MAIN_SHA, the rest from the harness checkout.
    commit: c.kind === "show4" ? MAIN_FULL : HEAD,
    circuit_commit: c.kind === "show4" ? MAIN_FULL : HEAD,
    harness_commit: HEAD,
    spartan2_rev: "n/a:circuit-only",
    ts: new Date().toISOString(),
  };
}

/** Recompiles r1cs+sym only, checks the r1cs is byte-identical to the one the wasm and witnesses came from, and keeps the sym. */
async function addSym(c: Cell): Promise<void> {
  const dir = path.join(buildDir, c.name);
  const row = [...allRows()].find((r) => r.cell === c.name);
  if (!row) throw new Error(`no SHAPE row for ${c.name}`);
  const scratch = { ...c, name: c.name, wasm: false };
  const tmp = path.join(dir, "_sym");
  fs.rmSync(tmp, { recursive: true, force: true });
  fs.mkdirSync(tmp, { recursive: true });
  const main = path.join(tmp, `${c.name}.circom`);
  fs.writeFileSync(main, mainSource(scratch));
  const lib = path.join(circomDir, "circuits");
  const log = fs.openSync(path.join(outDir(), "logs", `${c.name}.sym.log`), "w");
  await new Promise<void>((resolve, reject) => {
    const p = spawn("circom", [main, "--r1cs", "--sym", "-p", "secq256r1", "--O2", "-l", lib, "-l", path.join(circomDir, "node_modules"), "-l", path.join(circomDir, "node_modules/circomlib/circuits"), "-o", tmp], { stdio: ["ignore", log, log] });
    p.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`circom failed for ${c.name} (sym)`))));
  });
  fs.closeSync(log);
  const sha = sha256File(path.join(tmp, `${c.name}.r1cs`));
  if (sha !== row.r1cs_sha256) throw new Error(`${c.name}: recompiled r1cs differs from the one the wasm came from`);
  fs.renameSync(path.join(tmp, `${c.name}.sym`), path.join(dir, `${c.name}.sym`));
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`${c.name}: sym added, r1cs identical`);
}

const allRows = (): any[] => (fs.existsSync(shapePath()) ? fs.readFileSync(shapePath(), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);

async function run(c: Cell): Promise<void> {
  const built = c.reuse
    ? { ...c.reuse, seconds: null, peakBytes: null }
    : await compile(c);
  const row = shapeRow(c, built);
  fs.appendFileSync(shapePath(), JSON.stringify(row) + "\n");
  if (!c.reuse) {
    fs.rmSync(built.r1cs.replace(/\.r1cs$/, ".sym"), { force: true });
    if (!c.wasm && !keepR1cs) fs.rmSync(built.r1cs, { force: true });
  }
  console.log(`${c.name}: ${row.constraints} constraints, ${row.wires} wires${row.compile_s ? ` (${row.compile_s}s)` : ""}`);
}

async function main(): Promise<void> {
  fs.mkdirSync(path.join(outDir(), "logs"), { recursive: true });
  const matrix = flag("--matrix");
  const only = flag("--only")?.split(",");
  const symOnly = args.includes("--sym-only");
  const skip = force || symOnly ? new Set<string>() : done();
  const queue = allCells().filter(
    (c) => (!matrix || c.matrix === matrix) && (!only || only.includes(c.name)) && !skip.has(c.name) && (!symOnly || (c.wasm && !c.reuse)),
  );
  if (args.includes("--list")) {
    for (const c of queue) console.log(`${c.matrix}\t${c.name}\t${c.kind}\t[${c.params}]${c.wasm ? "\twasm" : ""}${c.heavy ? "\theavy" : ""}`);
    return;
  }
  if (queue.some((c) => c.kind === "show4")) ensureMainSource();

  // Heavy cells take both slots.
  const running = new Set<Promise<void>>();
  let weight = 0;
  for (const c of queue) {
    const w = c.heavy ? jobs : 1;
    while (running.size > 0 && weight + w > jobs) await Promise.race(running);
    weight += w;
    const p: Promise<void> = (symOnly ? addSym(c) : run(c))
      .catch((e) => console.error(String(e)))
      .finally(() => {
        weight -= w;
        running.delete(p);
      });
    running.add(p);
  }
  await Promise.all(running);
}

main();
