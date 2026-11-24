import assert from "assert";
import { execFileSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { IssuerRegistry, sha256Scheme as issuerScheme } from "@coordination-network/issuer-registry";
import { RevocationRegistry, sha256Scheme as revScheme } from "@coordination-network/revocation-registry";
import { buildSeededRevocationRegistry, seededCommitments } from "../../src/seeded-registries.ts";
import { issuerSyncBody, revocationSyncBody, serverJsonBytes } from "../../scripts/benchmarks/registry-bandwidth.ts";
import { ISSUER_MAX_DEPTH, ROUTE_OPS, issuerRootRebuilds, revocationRootRebuilds } from "../../scripts/benchmarks/registry-ops.ts";

const circomDir = path.join(__dirname, "..", "..");
type Row = Record<string, any>;

function smokeRun(extra: string[]): { rows: Row[]; stdout: string } {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bench-root-"));
  try {
    const stdout = execFileSync(path.join(circomDir, "node_modules/.bin/tsx"), ["scripts/benchmarks/registry-bench.ts", "--smoke", ...extra], {
      cwd: circomDir,
      env: { ...process.env, OPENACPLUS_BENCH_ROOT: root, NODE_OPTIONS: "--expose-gc" },
      encoding: "utf8",
      maxBuffer: 1 << 26,
    });
    const file = path.join(root, "registry", "smoke", "registry-smoke.jsonl");
    return { rows: fs.readFileSync(file, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)), stdout };
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

const replacer = (_k: string, v: unknown) => (typeof v === "bigint" ? v.toString() : v);

describe("registry bench ops", function () {
  this.timeout(900000);
  let smoke: { rows: Row[]; stdout: string };
  before(() => {
    smoke = smokeRun([]);
  });

  it("emits an op for every server route in --smoke mode", () => {
    assert.ok(ROUTE_OPS.length >= 13);
    for (const r of ROUTE_OPS) {
      const hit = smoke.rows.filter((x) => x.registry === r.registry && x.op === r.op && (r.method === undefined || x.method === r.method) && (r.k === undefined || x.k === r.k));
      assert.ok(hit.length > 0, `no row for ${r.route} -> ${r.registry}/${r.op}${r.method ? `/${r.method}` : ""}${r.k ? ` k=${r.k}` : ""}`);
    }
  });

  it("checks every mutating op against a fromLeaves rebuild, and every sync and lookup, with no errors", () => {
    const mutating = ["revoke", "revoke_many", "unrevoke", "update", "insert", "insert_many", "remove", "sync", "lookup"];
    const rows = smoke.rows.filter((r) => mutating.includes(r.op));
    assert.ok(rows.length > 0);
    for (const r of rows) assert.strictEqual(r.ok, true, `${r.registry}/${r.op} k=${r.k} iter=${r.iter}`);
    assert.ok(smoke.rows.every((r) => r.ok !== false));
    assert.match(smoke.stdout, /errors 0/);
  });

  it("runs every mutating iteration on a fresh tree", () => {
    for (const op of ["revoke_many", "unrevoke", "update", "insert", "remove"]) {
      const rows = smoke.rows.filter((r) => r.op === op);
      const byK = new Map<unknown, Set<unknown>>();
      for (const r of rows) byK.set(`${r.registry}|${r.k}`, (byK.get(`${r.registry}|${r.k}`) ?? new Set()).add(r.entries_before));
      for (const [key, sizes] of byK) assert.strictEqual(sizes.size, 1, `${op} ${String(key)} grew between iterations: ${[...sizes]}`);
    }
  });

  it("measures the issuer insert from 255 to 256 entries at depth 8", () => {
    const rows = smoke.rows.filter((r) => r.registry === "issuer" && r.op === "insert");
    assert.ok(rows.length > 1);
    for (const r of rows) {
      assert.strictEqual(r.entries_before, 255);
      assert.strictEqual(r.entries_after, 256);
      assert.strictEqual(r.depth_after, ISSUER_MAX_DEPTH);
      assert.strictEqual(r.beyond_circuit, false);
    }
  });

  it("times micro-ops as 1000 calls per region and keeps fractional microseconds", () => {
    const micro = smoke.rows.filter((r) => ["lookup", "to_commitment", "witness_member", "witness_nonmember", "path_verify"].includes(r.op));
    assert.ok(micro.length > 0);
    for (const r of micro) assert.strictEqual(r.calls, 1000, `${r.registry}/${r.op}`);
    assert.ok(micro.some((r) => !Number.isInteger(r.wall_us)));
    assert.ok(smoke.rows.filter((r) => r.wall_us !== null).every((r) => typeof r.calls === "number"));
  });

  it("reports the GET body size for both registries without a timing", () => {
    const rows = smoke.rows.filter((r) => r.op === "bandwidth" && r.method === "full_sync");
    assert.deepStrictEqual(rows.map((r) => r.registry).sort(), ["issuer", "revocation"]);
    for (const r of rows) assert.strictEqual(r.wall_us, null);
  });

  it("builds populations exactly, with the revocation sentinel slot counted once", () => {
    const rev = smoke.rows.find((r) => r.registry === "revocation" && r.op === "build");
    assert.strictEqual(rev?.population, 1024);
    const reg = buildSeededRevocationRegistry(1024, 1);
    assert.strictEqual(reg.size, 1024);
    assert.strictEqual(reg.leafSlots.length, 1025);
    assert.strictEqual(new IssuerRegistry(seededCommitments("iss", 1, 256), issuerScheme).size, 256);
  });

  it("restricts a run to the populations in --pops", () => {
    const { rows } = smokeRun(["--pops", "1024"]);
    assert.ok(rows.length > 0);
    assert.ok(rows.every((r) => r.registry === "revocation" && r.population === 1024));
  });
});

describe("registry bench helpers", function () {
  this.timeout(900000);

  it("sizes full_sync as the JSON the server would send at 1024", () => {
    const reg = buildSeededRevocationRegistry(1024, 1);
    const body = {
      root: reg.root,
      depth: reg.depth,
      size: reg.size,
      rootDuration: 3600,
      leaves: reg.leafSlots.map(({ value, nextValue }) => ({ value, nextValue })),
    };
    const text = JSON.stringify(body, replacer);
    assert.strictEqual(serverJsonBytes(revocationSyncBody(reg)), Buffer.byteLength(text));
    assert.strictEqual(JSON.stringify(revocationSyncBody(reg), replacer), text);
    assert.ok(text.includes(`"value":"${reg.leafSlots[1].value}"`));
  });

  it("serves issuer leaves as decimal strings with the circuit depth cap", () => {
    const reg = new IssuerRegistry(seededCommitments("iss", 1, 256), issuerScheme);
    const text = JSON.stringify({ root: reg.root, depth: reg.depth, size: reg.size, maxDepth: 8, rootDuration: 3600, leaves: reg.leaves }, replacer);
    assert.strictEqual(serverJsonBytes(issuerSyncBody(reg)), Buffer.byteLength(text));
  });

  it("goes to depth 9 on the 257th issuer, which the server rejects", () => {
    const reg = new IssuerRegistry(seededCommitments("iss", 1, 256), issuerScheme);
    assert.strictEqual(reg.depth, ISSUER_MAX_DEPTH);
    reg.addIssuer(seededCommitments("iss-extra", 1, 1)[0]);
    assert.strictEqual(reg.size, 257);
    assert.strictEqual(reg.depth, ISSUER_MAX_DEPTH + 1);
  });

  it("detects a root that a fromLeaves rebuild does not reproduce", () => {
    const c = seededCommitments("rev", 3, 64);
    const reg = new RevocationRegistry(c, revScheme);
    assert.ok(revocationRootRebuilds(reg));
    reg.unrevoke(c[5]);
    reg.updateCommitment(c[6], seededCommitments("new", 3, 1)[0]);
    assert.ok(revocationRootRebuilds(reg));
    Object.defineProperty(reg, "root", { get: () => 1n });
    assert.ok(!revocationRootRebuilds(reg));
    const iss = new IssuerRegistry(seededCommitments("iss", 3, 16), issuerScheme);
    iss.removeIssuer(seededCommitments("iss", 3, 16)[2]);
    assert.ok(issuerRootRebuilds(iss));
  });

  it("builds the 1046528 revocation population exactly: one sentinel slot, depth 20", () => {
    const reg = buildSeededRevocationRegistry(1048576 - 2048, 1);
    assert.strictEqual(reg.size, 1048576 - 2048);
    assert.strictEqual(reg.leafSlots.length, 1048576 - 2048 + 1);
    assert.strictEqual(reg.depth, 20);
  });
});
