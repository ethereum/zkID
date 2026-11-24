/**
 * Builds Show inputs and witnesses for the timed sweep cells from the combined 2k default input:
 * re-pads to (N, M, T), attaches seeded registries and a policy, runs the wasm generator, checks the
 * witness against the r1cs, and appends one INPUT row per file set to variants/inputs.jsonl.
 *
 *   npx tsx scripts/benchmarks/build-inputs.ts [--base <show-2k.json>] [--only cell,cell] [--set timed|correctness|population] [--list]
 */
import { execSync } from "child_process";
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
// @ts-ignore - snarkjs ships no types
import * as snarkjs from "snarkjs";
import { buildRevocationWitness } from "../../src/revocation.ts";
import { generateIssuerMembershipInputs } from "../../src/issuer-hiding.ts";
import { buildSeededIssuerRegistry, buildSeededRevocationRegistry } from "../../src/seeded-registries.ts";
import { policyFor, repad, type ShowInput } from "./inputs.ts";
import { benchRoot } from "./provenance.ts";
import { readR1cs } from "./r1cs.ts";
import { allCells } from "./variants.ts";

const bench = () => path.join(benchRoot(), "variants");
const shapePath = () => path.join(bench(), "shape.jsonl");
const outDir = () => path.join(bench(), "inputs");
const SEED = 1;
// A dirty tree is marked so a row never claims a commit it was not built from.
const HEAD =
  execSync("git rev-parse HEAD", { cwd: __dirname }).toString().trim() +
  (execSync("git status --porcelain -- .", { cwd: __dirname }).toString().trim() ? "-dirty" : "");
const FULL = 1048576 - 2048;

const args = process.argv.slice(2);
const flag = (n: string) => (args.includes(n) ? args[args.indexOf(n) + 1] : undefined);
const basePath = () => flag("--base") ?? path.join(bench(), "headline", "show-2k.json");

interface Job {
  cell: string;
  workload: string;
  revoked: number;
  issuers: number;
  matrix: string;
}

/** One population for the whole S-D series: it fits the smallest tree (D=8) so only the depth varies. */
const SD_REVOKED = 128;
const SD_ISSUERS = 256;

export function jobs(set: string): Job[] {
  const out: Job[] = [];
  const cells = allCells().filter((c) => c.kind === "show" && c.matrix !== "X2" && c.matrix !== "S-B");
  const headline = "sn_show_n2";
  if (set === "timed" || set === "all") {
    out.push({ cell: headline, workload: "w1", revoked: FULL, issuers: 256, matrix: "A1" });
    out.push({ cell: headline, workload: "w1", revoked: SD_REVOKED, issuers: SD_ISSUERS, matrix: "S-D" });
    for (const c of cells) {
      const [, m, t] = c.params;
      if (c.name === headline) continue;
      if (c.matrix === "S-D") out.push({ cell: c.name, workload: "w1", revoked: SD_REVOKED, issuers: SD_ISSUERS, matrix: "S-D" });
      if (c.matrix === "S-N") out.push({ cell: c.name, workload: "w1", revoked: FULL, issuers: 256, matrix: "S-N" });
      if (c.matrix === "S-MT") {
        out.push({ cell: c.name, workload: "w3", revoked: FULL, issuers: 256, matrix: "S-MT" });
        if (m === 4 && t === 7) out.push({ cell: c.name, workload: "w2", revoked: FULL, issuers: 256, matrix: "W" });
      }
    }
  }
  if (set === "population" || set === "all") {
    for (const r of [1024, 32768]) out.push({ cell: headline, workload: "w1", revoked: r, issuers: 256, matrix: "S-P" });
  }
  if (set === "correctness" || set === "all") {
    for (const w of ["eq", "le", "ge"]) for (const tv of ["true", "false"]) {
      out.push({ cell: headline, workload: `${w}_${tv}`, revoked: FULL, issuers: 256, matrix: "W" });
    }
  }
  return out;
}

const shapeRows = (): Map<string, any> =>
  new Map(fs.readFileSync(shapePath(), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)).map((r) => [r.cell, r]));

const sha = (p: string) => crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");
const secretBytes = (limbs: string[]): Uint8Array => {
  const v = (BigInt(limbs[0]) << 128n) | BigInt(limbs[1]);
  return Uint8Array.from(Buffer.from(v.toString(16).padStart(64, "0"), "hex"));
};
/** Replaces the row for the same (cell, workload, revoked) or appends; re-runs never duplicate. */
function upsertRow(row: Record<string, any>): void {
  const file = path.join(bench(), "inputs.jsonl");
  const key = (r: Record<string, any>) => `${r.cell}|${r.workload}|${r.population.revoked}`;
  const rows: Record<string, any>[] = fs.existsSync(file) ? fs.readFileSync(file, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [];
  const i = rows.findIndex((r) => key(r) === key(row));
  if (i === -1) rows.push(row);
  else rows[i] = row;
  fs.writeFileSync(file, rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
}

const bigintReplacer = (_k: string, v: unknown) => (typeof v === "bigint" ? v.toString() : v);

const regCache = new Map<string, any>();
const cached = <T>(key: string, make: () => T): T => {
  if (!regCache.has(key)) regCache.set(key, make());
  return regCache.get(key);
};

async function build(job: Job, shape: any, base: ShowInput): Promise<Record<string, unknown>> {
  const [n, m, t, , dIss, dRev] = shape.show_params as number[];
  const policy = policyFor(job.workload, m, t);
  const issuerReg = cached(`i${job.issuers}`, () =>
    buildSeededIssuerRegistry({ x: BigInt(base.issuerKeyX as string), y: BigInt(base.issuerKeyY as string) }, job.issuers, SEED),
  );
  const revReg = cached(`r${job.revoked}`, () => buildSeededRevocationRegistry(job.revoked, SEED));
  const issuer = { x: BigInt(base.issuerKeyX as string), y: BigInt(base.issuerKeyY as string) };

  const input = {
    ...repad(base, { n, m, t }, policy),
    ...generateIssuerMembershipInputs(issuer, issuerReg, dIss),
    ...buildRevocationWitness(secretBytes(base.revocationSecret as string[]), revReg, dRev),
  };

  const dir = path.join(outDir(), job.cell);
  fs.mkdirSync(dir, { recursive: true });
  const stem = path.join(dir, `${job.workload}-r${job.revoked}`);
  fs.writeFileSync(`${stem}.json`, JSON.stringify(input, bigintReplacer, 2));
  await snarkjs.wtns.calculate(JSON.parse(fs.readFileSync(`${stem}.json`, "utf8")), shape.wasm_path, `${stem}.wtns`);

  const check = readR1cs(shape.r1cs_path, `${stem}.wtns`);
  const w: bigint[] = (await snarkjs.wtns.exportJson(`${stem}.wtns`)).slice(1, 6).map(BigInt);
  const rootsOk =
    ((w[1] << 128n) + w[2] === issuerReg.root) && ((w[3] << 128n) + w[4] === revReg.root);
  const resultOk = w[0] === BigInt(policy.expected);
  const roots = { issuerRoot: issuerReg.root.toString(), revocationRoot: revReg.root.toString() };
  fs.writeFileSync(`${stem}.roots.json`, JSON.stringify(roots, null, 2));

  return {
    kind: "INPUT",
    cell: job.cell,
    matrix_id: job.matrix,
    workload: job.workload,
    show_params: shape.show_params,
    population: { issuers: issuerReg.size, revoked: revReg.size },
    seed: SEED,
    expected_result: policy.expected,
    input_path: `${stem}.json`,
    wtns_path: `${stem}.wtns`,
    input_sha256: sha(`${stem}.json`),
    wtns_sha256: sha(`${stem}.wtns`),
    r1cs_path: shape.r1cs_path,
    sym_path: fs.existsSync(shape.r1cs_path.replace(/\.r1cs$/, ".sym")) ? shape.r1cs_path.replace(/\.r1cs$/, ".sym") : null,
    wtns_check: check.satisfied === true,
    roots_match_circuit: rootsOk,
    result_matches_policy: resultOk,
    ...roots,
    commit: HEAD,
    circuit_commit: shape.circuit_commit ?? shape.commit,
    ts: new Date().toISOString(),
  };
}

async function main(): Promise<void> {
  const set = flag("--set") ?? "all";
  const only = flag("--only")?.split(",");
  const todo = jobs(set).filter((j) => !only || only.includes(j.cell));
  if (args.includes("--list")) {
    for (const j of todo) console.log(`${j.matrix}\t${j.cell}\t${j.workload}\tissuers=${j.issuers}\trevoked=${j.revoked}`);
    return;
  }
  const base: ShowInput = JSON.parse(fs.readFileSync(basePath(), "utf8"));
  const shapes = shapeRows();
  fs.mkdirSync(outDir(), { recursive: true });
  for (const job of todo) {
    const shape = shapes.get(job.cell);
    if (!shape?.wasm_path || !fs.existsSync(shape.wasm_path) || !fs.existsSync(shape.r1cs_path)) {
      console.log(`skip ${job.cell}/${job.workload}: not compiled yet`);
      continue;
    }
    const row = await build(job, shape, base);
    upsertRow(row);
    const ok = row.wtns_check && row.roots_match_circuit && row.result_matches_policy;
    console.log(`${ok ? "ok  " : "FAIL"} ${job.cell}/${job.workload} revoked=${job.revoked}`);
  }
}

if (require.main === module) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
