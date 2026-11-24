/**
 * Registry operations the off-chain server performs, timed as direct package calls: no HTTP, no
 * whole-tree export/import around each write, no file persistence.
 */
import { IssuerRegistry, sha256Scheme as issuerScheme, toCommitment as issuerToCommitment } from "@coordination-network/issuer-registry";
import { PROOF_TYPE, RevocationRegistry, sha256Scheme as revScheme, toCommitment as revToCommitment } from "@coordination-network/revocation-registry";
import { seededCommitments } from "../../src/seeded-registries.ts";
import { changedLeafCount, issuerMirrorBytes, issuerSyncBody, mirrorMinBytes, mirrorUpdateBytes, proofFetchBytes, revocationSyncBody, serverJsonBytes, type LeafRecord } from "./registry-bandwidth.ts";

export const ISSUER_MAX_DEPTH = 8;
export const HEAVY = 100_000;
const MICRO_CALLS = 1000;
const SEED = 1;

/** Server route to the bench op that stands in for it; `k` and `method` narrow which rows count. */
export const ROUTE_OPS: { route: string; registry: "issuer" | "revocation"; op: string; method?: string; k?: number }[] = [
  { route: "POST /revocation/commitments", registry: "revocation", op: "revoke_many", k: 1 },
  { route: "POST /revocation/commitments", registry: "revocation", op: "revoke_many", k: 100 },
  { route: "POST /revocation/commitments", registry: "revocation", op: "revoke_many", k: 1000 },
  { route: "DELETE /revocation/commitments/:c", registry: "revocation", op: "unrevoke" },
  { route: "PUT /revocation/commitments/:c", registry: "revocation", op: "update" },
  { route: "GET /revocation/commitments/:c", registry: "revocation", op: "lookup", method: "hit" },
  { route: "GET /revocation/commitments/:c", registry: "revocation", op: "lookup", method: "miss" },
  { route: "GET /revocation", registry: "revocation", op: "leaf_slots" },
  { route: "wallet sync (revocation)", registry: "revocation", op: "sync" },
  { route: "POST /issuer/commitments", registry: "issuer", op: "insert_many", k: 1 },
  { route: "POST /issuer/commitments", registry: "issuer", op: "insert_many", k: 100 },
  { route: "PUT /issuer/commitments/:c", registry: "issuer", op: "update" },
  { route: "DELETE /issuer/commitments/:c", registry: "issuer", op: "remove" },
  { route: "GET /issuer/commitments/:c", registry: "issuer", op: "lookup", method: "hit" },
  { route: "GET /issuer/commitments/:c", registry: "issuer", op: "lookup", method: "miss" },
  { route: "GET /issuer + wallet sync", registry: "issuer", op: "sync" },
  { route: "toCommitment before each write", registry: "revocation", op: "to_commitment" },
  { route: "toCommitment inside generateProof (not on issuer writes)", registry: "issuer", op: "to_commitment", method: "in_generate_proof" },
  { route: "GET body size", registry: "revocation", op: "bandwidth", method: "full_sync" },
  { route: "GET body size", registry: "issuer", op: "bandwidth", method: "full_sync" },
];

export interface BenchCtx {
  emit: (row: Record<string, unknown>) => void;
  gc: (() => void) | undefined;
  warm: number;
  heavyWarm: number;
}

/** A fromLeaves rebuild of the registry's physical slots must reproduce its root. */
export const revocationRootRebuilds = (r: RevocationRegistry): boolean => RevocationRegistry.fromLeaves(r.leafSlots, revScheme).root === r.root;
export const issuerRootRebuilds = (r: IssuerRegistry): boolean => IssuerRegistry.fromLeaves(r.leaves, issuerScheme).root === r.root;

/** One array of MICRO_CALLS probes per iteration, so a timed loop only indexes. */
const probeSets = (warm: number, at: (i: number, j: number) => bigint): bigint[][] =>
  Array.from({ length: warm + 1 }, (_, i) => Array.from({ length: MICRO_CALLS }, (_, j) => at(i, j)));

const heap = () => process.memoryUsage().heapUsed;

interface Region<S, T> {
  setup: (i: number) => S;
  run: (s: S, i: number, j: number) => T;
  /** Calls per timed region; `wall_us` is divided by it. */
  calls?: number;
  bytes?: (r: T) => number;
  /** Runs after the timer: verifies the result and may add row fields. */
  after?: (s: S, r: T, i: number) => Record<string, unknown>;
}

/**
 * Runs the region once cold, then `warm` more times, each its own row. `setup` runs outside the
 * timer, so a mutating op gets a fresh tree every iteration. Returns the last result.
 */
function region<S, T>(ctx: BenchCtx, base: Record<string, unknown>, warm: number, spec: Region<S, T>): T {
  let last!: T;
  const ops = Array.isArray(base.op) ? base.op : [base.op];
  const calls = spec.calls ?? 1;
  for (let i = 0; i <= warm; i++) {
    const s = spec.setup(i);
    ctx.gc?.();
    const t0 = process.hrtime.bigint();
    for (let j = 0; j < calls; j++) last = spec.run(s, i, j);
    const wallUs = Number(process.hrtime.bigint() - t0) / 1000 / calls;
    const extra = spec.after?.(s, last, i) ?? {};
    for (const op of ops) {
      ctx.emit({ ...base, op, iter: i, phase: i === 0 ? "cold" : "warm", wall_us: wallUs, calls, bytes: spec.bytes ? spec.bytes(last) : null, heap_used_bytes: heap(), ...extra });
    }
  }
  return last;
}

function timed<T>(ctx: BenchCtx, base: Record<string, unknown>, warm: number, fn: (i: number, j: number) => T, opts: { calls?: number; bytes?: (r: T) => number; after?: (r: T) => Record<string, unknown> } = {}): T {
  const { after, ...rest } = opts;
  return region(ctx, base, warm, { setup: () => undefined, run: (_s, i, j) => fn(i, j), after: after && ((_s, r) => after(r)), ...rest });
}

const modelRow = (ctx: BenchCtx, row: Record<string, unknown>) => ctx.emit({ iter: 0, phase: "model", wall_us: null, heap_used_bytes: heap(), ...row });

const withSentinel = (r: RevocationRegistry): LeafRecord[] => {
  const leaves = r.leaves;
  const min = leaves.reduce((m, l) => (m === 0n || l.value < m ? l.value : m), 0n);
  return [{ value: 0n, nextValue: min }, ...leaves];
};

/** A heavy population gets one root rebuild check, on its first iteration; a rebuild costs seconds there. */
const checks = (pop: number, i: number) => pop < HEAVY || i === 0;

function must(ok: boolean, what: string): void {
  if (!ok) throw new Error(`registry check failed: ${what}`);
}

export function benchRevocation(ctx: BenchCtx, pop: number): void {
  const warm = pop >= HEAVY ? ctx.heavyWarm : ctx.warm;
  const base = { registry: "revocation", population: pop, k: null as number | null };
  const holder = seededCommitments("holder-probe", SEED, 1)[0];
  const commitments = seededCommitments("rev", SEED, pop);
  const at = (i: number, j = 0) => commitments[((i * MICRO_CALLS + j) * 7919) % pop];
  const misses = seededCommitments("miss", SEED, MICRO_CALLS);
  const hits = probeSets(warm, at);

  const reg = timed(ctx, { ...base, op: "build" }, warm, () => new RevocationRegistry(commitments, revScheme));

  const proof = reg.generateProof(holder);
  if (proof.proofType !== PROOF_TYPE.NON_MEMBERSHIP) throw new Error("holder probe is revoked");
  const probes = seededCommitments("probe", SEED, MICRO_CALLS);
  timed(ctx, { ...base, op: "witness_nonmember" }, warm, (_i, j) => reg.generateProof(probes[j]), { calls: MICRO_CALLS });
  timed(ctx, { ...base, op: "witness_member" }, warm, (i, j) => reg.generateProof(hits[i][j]), { calls: MICRO_CALLS });
  // Root recompute is the wallet-side check: hash a proof's path back up to the root.
  timed(ctx, { ...base, op: "path_verify" }, warm, () => RevocationRegistry.verifyProof(proof, revScheme), { calls: MICRO_CALLS });

  timed(ctx, { ...base, op: "lookup", method: "hit" }, warm, (i, j) => reg.isRevoked(hits[i][j]), {
    calls: MICRO_CALLS,
    after: (revoked) => (must(revoked, "lookup hit"), { ok: true }),
  });
  timed(ctx, { ...base, op: "lookup", method: "miss" }, warm, (_i, j) => reg.isRevoked(misses[j]), {
    calls: MICRO_CALLS,
    after: (revoked) => (must(!revoked, "lookup miss"), { ok: true }),
  });
  timed(ctx, { ...base, op: "to_commitment" }, warm, (i, j) => revToCommitment(hits[i][j], revScheme), { calls: MICRO_CALLS });

  const snapshot = timed(ctx, { ...base, op: "export" }, warm, () => reg.export(), { bytes: (s) => s.length });
  const snapBytes = () => snapshot.length;
  timed(ctx, { ...base, op: "import", method: "validate=false" }, warm, () => RevocationRegistry.import(snapshot, false, revScheme), { bytes: snapBytes });
  if (pop <= 32768) timed(ctx, { ...base, op: "import", method: "validate=true" }, warm, () => RevocationRegistry.import(snapshot, true, revScheme), { bytes: snapBytes });

  const slots = withSentinel(reg);
  timed(ctx, { ...base, op: ["build", "root_recompute"], method: "fromLeaves" }, warm, () => RevocationRegistry.fromLeaves(slots, revScheme));

  // GET /revocation serves leafSlots; the wallet rebuilds from them and compares the served root.
  const servedRoot = reg.root;
  const served = timed(ctx, { ...base, op: "leaf_slots" }, warm, () => reg.leafSlots);
  timed(ctx, { ...base, op: "sync" }, warm, () => RevocationRegistry.fromLeaves(served, revScheme).root === servedRoot, {
    after: (ok) => (must(ok, "sync root"), { ok: true }),
  });

  const fresh = () => RevocationRegistry.import(snapshot, false, revScheme);
  const mutation = (op: string, k: number | null, spec: { run: (r: RevocationRegistry, i: number) => void; verify: (r: RevocationRegistry, i: number) => void }) =>
    region(ctx, { ...base, op, k }, warm, {
      setup: () => {
        const r = fresh();
        return { r, before: r.size };
      },
      run: ({ r }, i) => spec.run(r, i),
      after: ({ r, before }, _x, i) => {
        spec.verify(r, i);
        if (checks(pop, i)) must(revocationRootRebuilds(r), `${op} root vs fromLeaves rebuild`);
        return { ok: true, entries_before: before, entries_after: r.size };
      },
    });

  const single = seededCommitments("upd", SEED, warm + 1);
  mutation("revoke", null, { run: (r, i) => r.revoke(single[i]), verify: (r, i) => must(r.isRevoked(single[i]), "revoke") });
  for (const k of [1, 100, 1000]) {
    const batch = seededCommitments("upd-many", SEED + k, k);
    mutation("revoke_many", k, { run: (r) => r.revokeMany(batch), verify: (r) => must(batch.every((c) => r.isRevoked(c)), "revoke_many") });
  }
  mutation("unrevoke", null, { run: (r, i) => r.unrevoke(at(i)), verify: (r, i) => must(!r.isRevoked(at(i)), "unrevoke") });
  const renamed = seededCommitments("upd-new", SEED, warm + 1);
  mutation("update", null, {
    run: (r, i) => r.updateCommitment(at(i), renamed[i]),
    verify: (r, i) => must(r.isRevoked(renamed[i]) && !r.isRevoked(at(i)), "update"),
  });

  for (const k of [1, 100, 1000]) {
    const kBase = { ...base, k };
    const batch = seededCommitments("refresh", SEED + k, k);
    const before = withSentinel(fresh());

    // The wallet already holds S0, applies k updates, then asks for a proof; each run starts from a fresh S0.
    const applied = region(ctx, { ...kBase, op: "refresh_incremental", method: "revoke-loop" }, warm, {
      setup: fresh,
      run: (r) => {
        for (const c of batch) r.revoke(c);
        r.generateProof(holder);
        return r;
      },
    });

    const s1 = applied.export();
    timed(ctx, { ...kBase, op: "refresh_rebuild", method: "import" }, warm, () => RevocationRegistry.import(s1, false, revScheme).generateProof(holder), { bytes: () => s1.length });
    const s1Slots = withSentinel(applied);
    timed(ctx, { ...kBase, op: "refresh_rebuild", method: "fromLeaves" }, warm, () => RevocationRegistry.fromLeaves(s1Slots, revScheme).generateProof(holder));

    const changed = changedLeafCount(before, s1Slots);
    modelRow(ctx, { ...kBase, op: "bandwidth", method: "mirror_upper", bytes: mirrorUpdateBytes(changed), changed_leaves: changed });
    modelRow(ctx, { ...kBase, op: "bandwidth", method: "mirror_min", bytes: mirrorMinBytes(k), changed_leaves: changed });
    modelRow(ctx, { ...kBase, op: "bandwidth", method: "proof_fetch", bytes: proofFetchBytes("revocation", applied.depth), changed_leaves: changed, depth: applied.depth });
  }
  modelRow(ctx, { ...base, op: "bandwidth", method: "full_sync", bytes: serverJsonBytes(revocationSyncBody(reg)) });
  console.log(`revocation ${pop}: depth ${reg.depth}, snapshot ${(snapshot.length / 1e6).toFixed(1)} MB`);
}

export function benchIssuer(ctx: BenchCtx, pop: number): void {
  const warm = ctx.warm;
  const beyond = pop > 2 ** ISSUER_MAX_DEPTH;
  const base = { registry: "issuer", population: pop, k: null as number | null, beyond_circuit: beyond };
  const commitments = seededCommitments("iss", SEED, pop);
  const at = (i: number, j = 0) => commitments[((i * MICRO_CALLS + j) * 7919) % pop];
  const misses = seededCommitments("miss", SEED, MICRO_CALLS);
  const hits = probeSets(warm, at);

  const reg = timed(ctx, { ...base, op: "build" }, warm, () => new IssuerRegistry(commitments, issuerScheme));
  const proof = reg.generateProof(commitments[pop - 1]);
  timed(ctx, { ...base, op: "witness_member" }, warm, (i, j) => reg.generateProof(hits[i][j]), { calls: MICRO_CALLS });
  timed(ctx, { ...base, op: "path_verify" }, warm, () => IssuerRegistry.verifyProof(proof, issuerScheme), { calls: MICRO_CALLS });
  timed(ctx, { ...base, op: "lookup", method: "hit" }, warm, (i, j) => reg.indexOf(hits[i][j]), {
    calls: MICRO_CALLS,
    after: (index) => (must(index >= 0, "lookup hit"), { ok: true }),
  });
  timed(ctx, { ...base, op: "lookup", method: "miss" }, warm, (_i, j) => reg.indexOf(misses[j]), {
    calls: MICRO_CALLS,
    after: (index) => (must(index === -1, "lookup miss"), { ok: true }),
  });
  // The issuer authority never calls toCommitment on writes; only generateProof does, so this is that cost.
  timed(ctx, { ...base, op: "to_commitment", method: "in_generate_proof" }, warm, (i, j) => issuerToCommitment(hits[i][j], issuerScheme), { calls: MICRO_CALLS });

  const snapshot = timed(ctx, { ...base, op: "export" }, warm, () => reg.export(), { bytes: (s) => s.length });
  timed(ctx, { ...base, op: "import", method: "validate=false" }, warm, () => IssuerRegistry.import(snapshot, false, issuerScheme), { bytes: () => snapshot.length });

  // GET /issuer serves leaves; the wallet rebuilds from them and compares the served root.
  const servedRoot = reg.root;
  timed(ctx, { ...base, op: "sync" }, warm, () => IssuerRegistry.fromLeaves(reg.leaves, issuerScheme).root === servedRoot, {
    after: (ok) => (must(ok, "sync root"), { ok: true }),
  });

  const depthAtPop = reg.depth;
  modelRow(ctx, { ...base, op: "bandwidth", method: "mirror_upper", k: 1, bytes: issuerMirrorBytes(1) });
  modelRow(ctx, { ...base, op: "bandwidth", method: "mirror_min", k: 1, bytes: mirrorMinBytes(1) });
  modelRow(ctx, { ...base, op: "bandwidth", method: "proof_fetch", k: 1, bytes: proofFetchBytes("issuer", depthAtPop), depth: depthAtPop });
  modelRow(ctx, { ...base, op: "bandwidth", method: "full_sync", bytes: serverJsonBytes(issuerSyncBody(reg)) });

  const counted = (r: IssuerRegistry) => ({ r, before: r.size });
  const after = (op: string, r: IssuerRegistry, i: number, before: number) => {
    must(beyond || r.depth <= ISSUER_MAX_DEPTH, `${op} exceeded the circuit's issuer depth`);
    if (checks(pop, i)) must(issuerRootRebuilds(r), `${op} root vs fromLeaves rebuild`);
    return { ok: true, entries_before: before, entries_after: r.size, depth_after: r.depth };
  };

  // Inserts grow the population to its labelled size, so they start at pop - k entries.
  for (const [op, k] of [["insert", null], ["insert_many", 1], ["insert_many", 100]] as const) {
    const n = k ?? 1;
    const partial = new IssuerRegistry(commitments.slice(0, pop - n), issuerScheme).export();
    const added = commitments.slice(pop - n);
    region(ctx, { ...base, op, k }, warm, {
      setup: () => counted(IssuerRegistry.import(partial, false, issuerScheme)),
      run: ({ r }) => (k === null ? r.addIssuer(added[0]) : r.addIssuers(added)),
      after: ({ r, before }, _x, i) => {
        must(added.every((c) => r.isIssuer(c)), op);
        return after(op, r, i, before);
      },
    });
  }

  const fresh = () => counted(IssuerRegistry.import(snapshot, false, issuerScheme));
  const renamed = seededCommitments("iss-new", SEED, warm + 1);
  region(ctx, { ...base, op: "update" }, warm, {
    setup: fresh,
    run: ({ r }, i) => r.updateIssuerCommitment(at(i), renamed[i]),
    after: ({ r, before }, _x, i) => {
      must(r.isIssuer(renamed[i]) && !r.isIssuer(at(i)), "update");
      return after("update", r, i, before);
    },
  });
  region(ctx, { ...base, op: "remove" }, warm, {
    setup: fresh,
    run: ({ r }, i) => r.removeIssuer(at(i)),
    after: ({ r, before }, _x, i) => {
      must(!r.isIssuer(at(i)), "remove");
      return after("remove", r, i, before);
    },
  });
  console.log(`issuer ${pop}: depth ${depthAtPop}${beyond ? " (beyond the circuit)" : ""}`);
}
