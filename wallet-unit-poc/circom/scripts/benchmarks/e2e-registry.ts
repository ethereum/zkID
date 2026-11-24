/**
 * E1 registry-update and stale-root-retry workloads. The holder starts at registry state S0, the
 * verifier accepts only S1. Present against S0 (rejected on the root check), refresh to S1,
 * present again (accepted). Proving is a subprocess through the product path.
 *
 * Prover contract: the binary is run with --prover-args (default below), where {stage} {input}
 * {roots} {out} expand to the stage dir, the Show input JSON, the accepted-roots JSON and a work dir.
 * It prints one JSON line with ok, statement_ok, present_total_ms, show_prove_ms, verify_total_ms,
 * statement_check_ms and roots. The input's own presented roots are written to <input>.roots.json.
 *
 *   npx tsx scripts/benchmarks/e2e-registry.ts --bench-bin <path> --stage <stage dir> [--bench-bin <path>] [--revoked 1046528] [--k 100]
 *       [--iters 3] [--prover-args "present --stage {stage} --input {input} --expected-roots {roots} --out {out}"]
 *       [--base <show-2k.json>] [--out <jsonl>] [--smoke]
 *   Run with NODE_OPTIONS=--expose-gc so each timed region starts after a collection.
 *   OPENACPLUS_BENCH_ROOT is required: output goes under <root>/e2e and <root>/registry.
 */
import { execFileSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { assertSingleSetting, benchRoot, codeCommit, e2eFileName, requireGc } from "./provenance.ts";
import { buildRevocationWitness, computeRevocationCommitment } from "../../src/revocation.ts";
import { generateIssuerMembershipInputs } from "../../src/issuer-hiding.ts";
import { buildSeededIssuerRegistry, buildSeededRevocationRegistry, seededCommitments } from "../../src/seeded-registries.ts";
import { RevocationRegistry, sha256Scheme } from "@coordination-network/revocation-registry";

export interface Stage {
  name: string;
  wall_us: number;
  where: "mac" | "phone" | "node";
  /** 1 for the first presentation, 2 for the retry; each (name, attempt) appears once. */
  attempt?: number;
}

export interface Roots {
  issuerRoot: bigint;
  revocationRoot: bigint;
}

/** The verifier's root check: the presentation's roots must equal the roots it accepts. */
export function acceptPresentation(presented: Roots, accepted: Roots): { ok: true } | { ok: false; reason: "issuerRoot" | "revocationRoot" } {
  if (presented.issuerRoot !== accepted.issuerRoot) return { ok: false, reason: "issuerRoot" };
  if (presented.revocationRoot !== accepted.revocationRoot) return { ok: false, reason: "revocationRoot" };
  return { ok: true };
}

export function composeRow(workload: string, stages: Stage[], composed: boolean, extra: Record<string, unknown> = {}) {
  return { kind: "E2E", workload, stages, total_us: stages.reduce((s, x) => s + x.wall_us, 0), composed, ...extra };
}

export interface PresentParts {
  stages: Stage[];
  /** Overlapping or reported-apart timings: never summed into a total. */
  detail: { show_prove_ms: number; vk_load_ms: number | null; vk_digest_ms: number | null };
  vkInVerify: boolean;
  statementOk: boolean;
}

/**
 * Non-overlapping stages of one presentation. `present_total` already contains `show_prove`, and the
 * VK load stays in `detail` when the binary reports verify without it.
 */
export function presentStages(res: Record<string, any>, attempt: number, checkName: string, witnessInputsUs: number): PresentParts {
  const ms = (v: number) => Math.round(v * 1000);
  const vkInVerify = res.verify_ms === undefined;
  return {
    stages: [
      { name: "witness_inputs", wall_us: witnessInputsUs, where: "node", attempt },
      { name: "present_total", wall_us: ms(res.present_total_ms), where: "mac", attempt },
      vkInVerify
        ? { name: "verify_total", wall_us: ms(res.verify_total_ms), where: "mac", attempt }
        : { name: "verify", wall_us: ms(res.verify_ms), where: "mac", attempt },
      { name: checkName, wall_us: ms(res.statement_check_ms), where: "mac", attempt },
    ],
    detail: { show_prove_ms: res.show_prove_ms, vk_load_ms: res.vk_load_ms ?? null, vk_digest_ms: res.vk_digest_ms ?? null },
    vkInVerify,
    statementOk: res.statement_ok === true,
  };
}

/** registry_update is the wallet's refresh plus the retry presentation; stale_root_retry adds the rejected attempt. */
export function stalePair(first: PresentParts, refresh: Stage, second: PresentParts, meta: Record<string, unknown>) {
  const detail = { attempt1: first.detail, attempt2: second.detail, vk_in_verify: first.vkInVerify || second.vkInVerify };
  const refreshStage = { ...refresh, attempt: 2 };
  return [
    composeRow("registry_update", [refreshStage, ...second.stages], true, { ...meta, detail }),
    composeRow("stale_root_retry", [...first.stages, refreshStage, ...second.stages], true, { ...meta, detail }),
  ] as ReturnType<typeof composeRow>[];
}

const REGISTRY_FIELDS = new Set([
  "issuerTreeDepth", "issuerTreeIndex", "issuerTreeSiblings",
  "revocationLeafValue", "revocationLeafNextValue", "revocationLeafIndex", "revocationDepth", "revocationSiblings",
]);

/** The staged input carries the nonce and policy the statement check compares; only registry witness fields may differ. */
export function assertOnlyRegistryFieldsChanged(staged: Record<string, unknown>, built: Record<string, unknown>): void {
  for (const k of new Set([...Object.keys(staged), ...Object.keys(built)])) {
    const same = JSON.stringify(staged[k], bigintReplacer) === JSON.stringify(built[k], bigintReplacer);
    if (!same && !REGISTRY_FIELDS.has(k)) throw new Error(`input field ${k} differs from the staged input`);
  }
}

const bigintReplacer = (_k: string, v: unknown) => (typeof v === "bigint" ? v.toString() : v);

function secretBytes(limbs: string[]): Uint8Array {
  const v = (BigInt(limbs[0]) << 128n) | BigInt(limbs[1]);
  return Uint8Array.from(Buffer.from(v.toString(16).padStart(64, "0"), "hex"));
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const flag = (n: string) => (args.includes(n) ? args[args.indexOf(n) + 1] : undefined);
  const stageArg = flag("--stage");
  const benchBin = flag("--bench-bin") ?? (stageArg ? path.join(stageArg, "openac_bench") : undefined);
  if (!benchBin) throw new Error("--stage or --bench-bin is required");
  const bench = benchRoot();
  // The staged Show input: its nonce and policy must survive, so only registry fields are replaced.
  const base = JSON.parse(fs.readFileSync(flag("--base") ?? path.join(bench, "variants/headline/show-2k.json"), "utf8"));
  const revoked = Number(flag("--revoked") ?? 1048576 - 2048);
  const k = Number(flag("--k") ?? 100);
  const iters = Number(flag("--iters") ?? 3);
  const out = flag("--out") ?? path.join(bench, args.includes("--smoke") ? "e2e/smoke" : "e2e", e2eFileName(k, revoked));
  assertSingleSetting(out, k, revoked);
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "e2e-"));
  fs.mkdirSync(path.dirname(out), { recursive: true });

  const issuer = { x: BigInt(base.issuerKeyX), y: BigInt(base.issuerKeyY) };
  const issuerReg = buildSeededIssuerRegistry(issuer, 256, 1);
  const secret = secretBytes(base.revocationSecret);
  const maxDepth = base.revocationSiblings.length;

  const now = () => process.hrtime.bigint();
  const us = (t0: bigint) => Number(now() - t0) / 1000;

  const stageDir = flag("--stage") ?? "";
  const proverArgs = flag("--prover-args") ?? "present --stage {stage} --input {input} --expected-roots {roots} --out {out}";
  const expand = (t: string, m: Record<string, string>) => t.split(/\s+/).map((w) => w.replace(/\{(\w+)\}/g, (_, k) => m[k]));

  const gc = (globalThis as { gc?: () => void }).gc;
  requireGc(args.includes("--smoke") || benchBin.includes("stub"), gc);
  const quiesce = () => gc?.();
  const commitment = computeRevocationCommitment(secret);

  // Builds the Show input against `reg` and presents it; the binary does witness gen, proving and the statement check.
  const present = (reg: RevocationRegistry, tag: string, accepted: Roots, attempt: number, checkName: string): PresentParts => {
    quiesce();
    const t0 = now();
    const input = { ...base, ...generateIssuerMembershipInputs(issuer, issuerReg, 8), ...buildRevocationWitness(secret, reg, maxDepth) };
    const witnessUs = us(t0);
    assertOnlyRegistryFieldsChanged(base, input);
    const inPath = path.join(work, `${tag}.json`);
    const rootsPath = path.join(work, `${tag}.accepted.json`);
    fs.writeFileSync(inPath, JSON.stringify(input, bigintReplacer));
    fs.writeFileSync(`${inPath}.roots.json`, JSON.stringify({ issuerRoot: issuerReg.root, revocationRoot: reg.root }, bigintReplacer));
    fs.writeFileSync(rootsPath, JSON.stringify(accepted, bigintReplacer));
    const argv = expand(proverArgs, { stage: stageDir, input: inPath, roots: rootsPath, out: path.join(work, tag) });
    const stdout = execFileSync(benchBin, argv, { encoding: "utf8", maxBuffer: 1 << 28 });
    // witnesscalc also writes to stdout, so prefer present.json in --out and fall back to the last line.
    const outFile = path.join(work, tag, "present.json");
    const res = JSON.parse(fs.existsSync(outFile) ? fs.readFileSync(outFile, "utf8") : stdout.trim().split("\n").pop()!);
    if (!res.ok) throw new Error("prover reported failure");
    return presentStages(res, attempt, checkName, witnessUs);
  };

  // Warm the revoke and proof paths in this process before anything is timed.
  const warm = new RevocationRegistry(seededCommitments("e2e-warm", 1, 2000), sha256Scheme);
  for (const c of seededCommitments("e2e-warm-upd", 1, 50)) warm.revoke(c);
  warm.generateProof(commitment);

  const rows: unknown[] = [];
  const registryRows: unknown[] = [];
  const s0Reg = buildSeededRevocationRegistry(revoked, 1);
  const snapshot = s0Reg.export();
  const updates = seededCommitments("e2e-upd", 1, k * iters);
  const smoke = args.includes("--smoke") || benchBin.includes("stub");
  const prov = {
    smoke,
    command: `npx tsx scripts/benchmarks/e2e-registry.ts ${args.join(" ")}`,
    commit: codeCommit(__dirname),
    spartan2_rev: stageDir ? JSON.parse(fs.readFileSync(path.join(stageDir, "meta.json"), "utf8")).spartan2_rev ?? null : null,
    node_version: process.version,
  };

  for (let i = 0; i < iters; i++) {
    const holder = RevocationRegistry.import(snapshot, false, sha256Scheme); // wallet state S0
    const authority = RevocationRegistry.import(snapshot, false, sha256Scheme);
    const batch = updates.slice(i * k, (i + 1) * k);

    quiesce();
    let t0 = now();
    authority.revokeMany(batch); // S1
    registryRows.push({
      kind: "REGISTRY", registry: "revocation", op: "revoke_many", population: revoked, revoked, k, iter: i, phase: "warm",
      wall_us: us(t0), bytes: null, heap_used_bytes: process.memoryUsage().heapUsed, pkg_versions: null, source: "e2e", ...prov, spartan2_rev: "n/a:node-registry",
    });
    const accepted: Roots = { issuerRoot: issuerReg.root, revocationRoot: authority.root };

    const first = present(holder, `s0-${i}`, accepted, 1, "root_rejected");
    if (first.statementOk) throw new Error("stale presentation was accepted");

    // Same definition as REGISTRY refresh_incremental: apply k updates to the mirror, then regenerate the proof.
    quiesce();
    t0 = now();
    for (const c of batch) holder.revoke(c);
    holder.generateProof(commitment);
    const refreshStage: Stage = { name: "witness_refresh", wall_us: us(t0), where: "node" };

    const second = present(holder, `s1-${i}`, accepted, 2, "statement_check");
    if (!second.statementOk) throw new Error("refreshed presentation rejected");

    const meta = {
      iter: i, k, revoked, population: { issuers: issuerReg.size, revoked }, stub: benchBin.includes("stub"), bench_bin: benchBin,
      d_iss: 8, d_rev: maxDepth, platform: "macos", product_model: execFileSync("sysctl", ["-n", "hw.model"], { encoding: "utf8" }).trim(),
      gc_exposed: typeof gc === "function", ...prov,
    };
    rows.push(...stalePair(first, refreshStage, second, meta));
  }
  const registryOut = flag("--registry-out") ?? path.join(path.dirname(out), smoke ? "../registry/smoke/registry-e2e.jsonl" : "../registry/registry-e2e.jsonl");
  fs.mkdirSync(path.dirname(registryOut), { recursive: true });
  fs.appendFileSync(registryOut, registryRows.map((r) => JSON.stringify(r)).join("\n") + "\n");
  fs.appendFileSync(out, rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
  fs.rmSync(work, { recursive: true, force: true });
  console.log(`wrote ${rows.length} E2E rows to ${out}`);
}

if (require.main === module) main().catch((e) => { console.error(e); process.exit(1); });
