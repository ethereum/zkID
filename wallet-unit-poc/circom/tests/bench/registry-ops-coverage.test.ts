import assert from "assert";
import { spawnSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { IssuerRegistry } from "@coordination-network/issuer-registry";
import { RevocationRegistry } from "@coordination-network/revocation-registry";
import { HEAVY, ISSUER_MAX_DEPTH, benchIssuer, benchRevocation, type BenchCtx } from "../../scripts/benchmarks/registry-ops.ts";

const circomDir = path.join(__dirname, "..", "..");
type Row = Record<string, any>;

function collect(warm: number, heavyWarm = warm, onEmit?: (row: Row) => void): { ctx: BenchCtx; rows: Row[] } {
  const rows: Row[] = [];
  const ctx: BenchCtx = { gc: undefined, warm, heavyWarm, emit: (row) => (rows.push(row), onEmit?.(row)) };
  return { ctx, rows };
}

const spin = (us: number) => {
  const end = process.hrtime.bigint() + BigInt(us) * 1000n;
  while (process.hrtime.bigint() < end);
};

function run(args: string[], root: string) {
  return spawnSync(path.join(circomDir, "node_modules/.bin/tsx"), ["scripts/benchmarks/registry-bench.ts", ...args], {
    cwd: circomDir,
    env: { ...process.env, OPENACPLUS_BENCH_ROOT: root, NODE_OPTIONS: "--expose-gc" },
    encoding: "utf8",
    maxBuffer: 1 << 26,
  });
}

function cli(args: string[]): { rows: Row[]; status: number | null; stderr: string } {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bench-root-"));
  try {
    const out = path.join(root, "out.jsonl");
    const r = run([...args, "--out", out], root);
    const rows = fs.existsSync(out) ? fs.readFileSync(out, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [];
    return { rows, status: r.status, stderr: r.stderr };
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

const pairs = (rows: Row[]) => rows.map((r) => `${r.registry}:${r.population}`);

// Ops that SCHEMA.md lists for REGISTRY, plus the later pins and the server-route ops this bench adds.
const REGISTRY_OPS = [
  "build", "insert", "remove", "revoke", "revoke_many", "witness_member", "witness_nonmember", "root", "refresh_incremental", "refresh_rebuild", "export", "import",
  "bandwidth", "path_verify", "root_recompute",
  "insert_many", "unrevoke", "update", "lookup", "to_commitment", "leaf_slots", "sync",
];
const MICRO = ["lookup", "to_commitment", "witness_member", "witness_nonmember", "path_verify"];
const CHECKED = ["revoke", "revoke_many", "unrevoke", "update", "insert", "insert_many", "remove", "sync", "lookup"];
const MUTATING = ["revoke", "revoke_many", "unrevoke", "update", "insert", "insert_many", "remove"];

describe("registry bench: timing and checks", function () {
  this.timeout(900000);

  it("runs the root rebuild check on iteration 0 only at a heavy population, and on every iteration below it", () => {
    const orig = RevocationRegistry.fromLeaves;
    let calls = 0;
    RevocationRegistry.fromLeaves = ((...a: Parameters<typeof orig>) => (calls++, orig(...a))) as typeof orig;
    try {
      for (const [pop, heavy] of [[HEAVY, true], [1024, false]] as const) {
        let last = calls;
        const seen: { op: string; iter: number; rebuilds: number }[] = [];
        const { ctx } = collect(2, 2, (row) => {
          if (MUTATING.includes(row.op)) seen.push({ op: row.op, iter: row.iter, rebuilds: calls - last });
          last = calls;
        });
        benchRevocation(ctx, pop);
        assert.strictEqual(seen.length, 18);
        for (const s of seen) assert.strictEqual(s.rebuilds, heavy && s.iter > 0 ? 0 : 1, `pop ${pop} ${s.op} iter ${s.iter}`);
      }
    } finally {
      RevocationRegistry.fromLeaves = orig;
    }
  });

  it("keeps the verification pass out of the timed region", () => {
    const orig = RevocationRegistry.fromLeaves;
    let slow = 0;
    RevocationRegistry.fromLeaves = ((...a: Parameters<typeof orig>) => (spin(300_000), slow++, orig(...a))) as typeof orig;
    try {
      const { ctx, rows } = collect(1);
      benchRevocation(ctx, 64);
      assert.ok(slow > 0);
      const single = rows.filter((r) => ["revoke", "unrevoke", "update"].includes(r.op));
      assert.strictEqual(single.length, 6);
      for (const r of single) assert.ok(r.wall_us < 100_000, `${r.op} iter ${r.iter} wall_us ${r.wall_us}`);
    } finally {
      RevocationRegistry.fromLeaves = orig;
    }
  });

  it("keeps per-iteration setup out of the timed region", () => {
    const orig = IssuerRegistry.import;
    let slow = 0;
    let armed = false;
    IssuerRegistry.import = ((...a: Parameters<typeof orig>) => (armed && (spin(300_000), slow++), orig(...a))) as typeof orig;
    try {
      // Arm after the timed import op, so only the setup imports of the mutating ops are slow.
      const { ctx, rows } = collect(1, 1, (row) => {
        if (row.op === "import") armed = true;
      });
      benchIssuer(ctx, 256);
      assert.ok(slow >= 8);
      const mutating = rows.filter((r) => ["insert", "insert_many", "update", "remove"].includes(r.op));
      assert.ok(mutating.length >= 10);
      for (const r of mutating) assert.ok(r.wall_us < 100_000, `${r.op} k=${r.k} iter ${r.iter} wall_us ${r.wall_us}`);
    } finally {
      IssuerRegistry.import = orig;
    }
  });

  it("divides a micro-op region by its 1000 calls", () => {
    const orig = RevocationRegistry.prototype.isRevoked;
    RevocationRegistry.prototype.isRevoked = function (this: RevocationRegistry, c: bigint) {
      spin(200);
      return orig.call(this, c);
    };
    try {
      const { ctx, rows } = collect(1);
      benchRevocation(ctx, 64);
      const hits = rows.filter((r) => r.op === "lookup" && r.method === "hit");
      assert.strictEqual(hits.length, 2);
      for (const r of hits) assert.ok(r.wall_us >= 200 && r.wall_us < 5000, `wall_us ${r.wall_us}`);
    } finally {
      RevocationRegistry.prototype.isRevoked = orig;
    }
  });

  it("runs the mutating ops from a fresh tree every iteration, in both registries", () => {
    const { ctx, rows } = collect(2);
    benchIssuer(ctx, 256);
    benchRevocation(ctx, 128);
    for (const op of MUTATING) {
      const mine = rows.filter((r) => r.op === op);
      assert.ok(mine.length > 0, op);
      const groups = new Map<string, Row[]>();
      for (const r of mine) groups.set(`${r.registry}|${r.k}`, [...(groups.get(`${r.registry}|${r.k}`) ?? []), r]);
      for (const [key, g] of groups) {
        assert.strictEqual(g.length, 3, `${op} ${key}`);
        assert.strictEqual(new Set(g.map((r) => r.entries_before)).size, 1, `${op} ${key} entries_before`);
        assert.strictEqual(new Set(g.map((r) => r.entries_after - r.entries_before)).size, 1, `${op} ${key} growth`);
      }
    }
  });
});

describe("registry bench: smoke rows", function () {
  this.timeout(900000);
  let rows: Row[];
  before(() => {
    const r = cli(["--smoke"]);
    assert.strictEqual(r.status, 0, r.stderr);
    rows = r.rows;
  });

  it("gives every row the REGISTRY fields, a numeric wall_us (null for bandwidth) and a commit stamp", () => {
    assert.ok(rows.length > 50);
    for (const r of rows) {
      const id = `${r.registry}/${r.op}/${r.method} iter=${r.iter}`;
      assert.strictEqual(r.kind, "REGISTRY", id);
      assert.ok(["issuer", "revocation"].includes(r.registry), id);
      assert.ok(REGISTRY_OPS.includes(r.op), `unknown op ${id}`);
      assert.strictEqual(typeof r.population, "number", id);
      assert.ok(Number.isInteger(r.iter) && r.iter >= 0, id);
      assert.ok(["cold", "warm", "model"].includes(r.phase), id);
      assert.strictEqual(r.phase === "cold", r.iter === 0 && r.op !== "bandwidth", id);
      assert.strictEqual(r.wall_us === null, r.op === "bandwidth", id);
      if (r.wall_us !== null) assert.ok(typeof r.wall_us === "number" && r.wall_us >= 0, id);
      assert.strictEqual(typeof r.calls, "number", id);
      assert.notStrictEqual(r.ok, false, id);
      assert.match(r.commit, /^[0-9a-f]{40}(-dirty)?$/, id);
    }
  });

  it("marks every checked op ok: true", () => {
    const checked = rows.filter((r) => CHECKED.includes(r.op));
    assert.ok(checked.length > 0);
    for (const r of checked) assert.strictEqual(r.ok, true, `${r.registry}/${r.op} k=${r.k} iter=${r.iter}`);
  });

  it("reports calls 1000 for micro-ops and 1 for everything else", () => {
    for (const r of rows) assert.strictEqual(r.calls, MICRO.includes(r.op) ? 1000 : 1, `${r.registry}/${r.op}/${r.method}`);
  });

  it("keeps every issuer mutating op at 256 within the circuit depth", () => {
    const issuer = rows.filter((r) => r.registry === "issuer" && ["insert", "insert_many", "update", "remove"].includes(r.op));
    assert.strictEqual(issuer.length, 10);
    for (const r of issuer) {
      assert.strictEqual(r.population, 256);
      assert.ok(r.depth_after <= ISSUER_MAX_DEPTH, `${r.op} k=${r.k} depth_after ${r.depth_after}`);
    }
  });
});

describe("registry bench: --pops", function () {
  this.timeout(900000);

  it("runs only the issuer beyond-circuit population for --pops 65536", () => {
    const r = cli(["--warm", "1", "--heavy-warm", "1", "--pops", "65536"]);
    assert.strictEqual(r.status, 0, r.stderr);
    assert.ok(r.rows.length > 0);
    for (const row of r.rows) {
      assert.strictEqual(row.registry, "issuer");
      assert.strictEqual(row.population, 65536);
      assert.strictEqual(row.beyond_circuit, true);
    }
  });

  it("fails on a value that matches no population", () => {
    const r = cli(["--smoke", "--pops", "7"]);
    assert.notStrictEqual(r.status, 0);
    assert.match(r.stderr, /--pops 7 matches no population/);
    assert.strictEqual(r.rows.length, 0);
  });

  it("filters --revocation-pops and --issuer-pops with --pops", () => {
    const a = cli(["--smoke", "--revocation-pops", "1024,2048", "--pops", "2048"]);
    assert.strictEqual(a.status, 0, a.stderr);
    assert.deepStrictEqual([...new Set(pairs(a.rows))], ["revocation:2048"]);

    const b = cli(["--smoke", "--revocation-pops", "512", "--issuer-pops", "128,256", "--pops", "128,512"]);
    assert.strictEqual(b.status, 0, b.stderr);
    assert.deepStrictEqual([...new Set(pairs(b.rows))].sort(), ["issuer:128", "revocation:512"]);

    const c = cli(["--smoke", "--revocation-pops", "2048", "--pops", "1024"]);
    assert.notStrictEqual(c.status, 0);
    assert.match(c.stderr, /matches no population/);
  });
});
