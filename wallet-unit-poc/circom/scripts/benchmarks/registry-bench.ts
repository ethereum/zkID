/**
 * Times @coordination-network registry operations and appends REGISTRY rows.
 *
 *   OPENACPLUS_BENCH_ROOT=<dir> NODE_OPTIONS=--max-old-space-size=32768 npx tsx scripts/benchmarks/registry-bench.ts \
 *     [--pops 1024] [--revocation-pops 1024,32768,1046528] [--issuer-pops 256,65536] [--warm 5] [--heavy-warm 5] [--smoke] [--out path]
 * Run with --expose-gc in NODE_OPTIONS; each timed region starts after a collection. --pops keeps only the
 * listed populations, so each population can run in its own process.
 */
import * as fs from "fs";
import * as path from "path";
import { benchRoot, codeCommit, requireGc } from "./provenance.ts";
import { benchIssuer, benchRevocation, type BenchCtx } from "./registry-ops.ts";

const args = process.argv.slice(2);
const flag = (n: string) => (args.includes(n) ? args[args.indexOf(n) + 1] : undefined);
const list = (n: string, d: number[]) => (flag(n) ? flag(n)!.split(",").map(Number) : d);
const smoke = args.includes("--smoke");
const WARM = Number(flag("--warm") ?? (smoke ? 1 : 5));
const HEAVY_WARM = Number(flag("--heavy-warm") ?? (smoke ? 1 : 5));
const OUT = flag("--out") ?? path.join(benchRoot(), "registry", smoke ? "smoke/registry-smoke.jsonl" : "registry.jsonl");
const gc = (globalThis as { gc?: () => void }).gc;
requireGc(smoke, gc);

const pkgVersion = (name: string): string => {
  return JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "node_modules", name, "package.json"), "utf8")).version;
};
const PKGS = Object.fromEntries(
  ["@coordination-network/revocation-registry", "@coordination-network/issuer-registry", "@zk-kit/lean-imt", "@zk-kit/lean-imt-plus", "@noble/hashes"].map(
    (n) => [n, pkgVersion(n)],
  ),
);
const COMMIT = codeCommit(__dirname);
const COMMAND = `npx tsx scripts/benchmarks/registry-bench.ts ${args.join(" ")}`.trim();

fs.mkdirSync(path.dirname(OUT), { recursive: true });

let rows = 0;
let errors = 0;
function emit(row: Record<string, unknown>): void {
  if (row.ok === false) errors++;
  rows++;
  const bytes = typeof row.bytes === "number" && typeof row.k === "number" && row.k > 0 ? { bytes_per_update: row.bytes / row.k } : {};
  fs.appendFileSync(
    OUT,
    JSON.stringify({ kind: "REGISTRY", calls: 1, ...row, ...bytes, gc_exposed: typeof gc === "function", node_version: process.version, pkg_versions: PKGS, commit: COMMIT, command: COMMAND, spartan2_rev: "n/a:node-registry", smoke, ts: new Date().toISOString() }) + "\n",
  );
}

const only = flag("--pops")?.split(",").map(Number);
const pick = (n: string, d: number[]) => list(n, d).filter((p) => !only || only.includes(p));
const issuerPops = pick("--issuer-pops", smoke ? [256] : [256, 65536]);
const revocationPops = pick("--revocation-pops", smoke ? [1024] : [1024, 32768, 1048576 - 2048]);
if (issuerPops.length + revocationPops.length === 0) throw new Error(`--pops ${flag("--pops")} matches no population`);

const ctx: BenchCtx = { emit, gc, warm: WARM, heavyWarm: HEAVY_WARM };
for (const p of issuerPops) benchIssuer(ctx, p);
for (const p of revocationPops) benchRevocation(ctx, p);
console.log(`${rows} rows, errors ${errors}, written to ${OUT}`);
