"""Composes the E1 workloads (import, warm, cold, refill) from measured ITER steps, one E2E row per iteration or visit."""
from collections import defaultdict

from bench import population

BATCHES = (1, 8, 32, 128)
TARGETS = ("mac", "iphone17pro", "s26plus")
IMPORT = ["prepare_witness", "prepare_prove", "prepare_reblind"]
WARM = ["present_total", "verify", "statement_check"]
COLD_LOADS = ["key_load_prepare", "key_load_show", "vk_load"]
STATE_NOTE = "prepared state held in memory, not loaded from storage"
COLD_RUN = ["present_total", "verify", "statement_check"]
PROVENANCE = ("bench_sha", "base_sha", "commit", "spartan2_rev", "command", "run_id")


def _row(ds, cell, workload, stages, where, batch=None):
    meta = ds.metas[cell][0]
    pops = population(meta)
    row = {"kind": "E2E", "workload": workload, "config": cell[1], "matrix_id": "E1", "_target": cell[0],
           "composed": True, "_derived": True, "batch": batch, "k": None,
           "population": {"issuers": pops[0], "revoked": pops[1]}, "d_iss": meta.get("d_iss"), "d_rev": meta.get("d_rev"),
           "stages": [{"name": n, "wall_us": v * 1000, "where": where} for n, v in stages],
           "total_us": sum(v for _, v in stages) * 1000,
           "_src": ";".join(sorted({s for s, _ in ds.sources(cell) if s}))}
    row.update({k: meta[k] for k in PROVENANCE if meta.get(k) is not None})
    return row


def _by_iteration(ds, cell, steps, phase="warm"):
    """{(process, iter): {step: ms}} for iterations that have every step."""
    got = defaultdict(dict)
    for s in steps:
        for o in ds.obs(cell, s, phase):
            got[(o.proc, o.iter)][s] = o.v
    return [(k, v) for k, v in sorted(got.items()) if all(s in v for s in steps)]


def _cold(ds, cell, mac):
    """(visits, stage names, missing): `state_load` is optional because Mac product cells run Prepare in-process."""
    required = COLD_LOADS + (["vk_digest"] if mac else []) + COLD_RUN
    got = defaultdict(dict)
    for s in required + ["state_load"]:
        for phase in ("first", "cold"):
            for o in ds.obs(cell, s, phase):
                if s == "vk_load" and not (o.vk is not None and {"prepare", "show"} <= set(o.vk)):
                    continue
                if o.iter == 0:
                    got[o.proc].setdefault(s, o.v)
    with_state = any("state_load" in v for v in got.values())
    steps = COLD_LOADS[:2] + (["state_load"] if with_state else []) + required[2:]
    visits = [v for _, v in sorted(got.items()) if all(s in v for s in steps)]
    missing = [s for s in required if not any(s in v for v in got.values())]
    return visits, steps, missing, not with_state


def compose(ds, batches=BATCHES):
    have = {(r.get("_target"), r.get("workload")) for r in ds.e2e if r.get("composed") and not r.get("_derived")}
    for target in TARGETS:
        cell = ds.pick(target, "combined", "A1", d_iss=8, d_rev=20, jwt_size="2k")
        if not cell:
            continue
        mac, where = target == "mac", ("mac" if target == "mac" else "phone")
        for workload, steps in (("import", IMPORT), ("warm", WARM)):
            if (target, workload) not in have:
                for _, vals in _by_iteration(ds, cell, steps):
                    ds.e2e.append(_row(ds, cell, workload, [(s, vals[s]) for s in steps], where))
        if (target, "cold") not in have:
            visits, steps, missing, in_memory = _cold(ds, cell, mac)
            if not visits:
                ds.cold_skipped.append((cell, missing))
            for vals in visits:
                r = _row(ds, cell, "cold", [(s, vals[s]) for s in steps], where)
                if in_memory:
                    r["state_in_memory"] = True
                ds.e2e.append(r)
        if (target, "refill") in have:
            continue
        sb = {ds.meta[c].get("batch"): c for c in ds.cells() if c[0] == target and c[2] == "S-B" and ds.meta[c].get("batch")}
        for b in batches:
            if b in sb and ds.obs(sb[b], "batch_reblind"):
                for o in ds.obs(sb[b], "batch_reblind"):
                    ds.e2e.append(_row(ds, sb[b], "refill", [("batch_reblind", o.v)], where, batch=b))
            else:
                for o in ds.obs(cell, "prepare_reblind"):
                    ds.e2e.append(_row(ds, cell, "refill", [("prepare_reblind", o.v * b)], where, batch=b))
