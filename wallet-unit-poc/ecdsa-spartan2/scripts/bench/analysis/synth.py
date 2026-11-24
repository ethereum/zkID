"""Synthetic rows in the SCHEMA.md shape, for tests and CLI smoke runs."""
import json
import os

STEPS = ("statement_check", "state_load", "key_load_prepare", "key_load_show", "vk_digest", "prepare_witness", "prepare_prove", "prepare_reblind", "prepare_total", "show_prove",
         "show_reblind", "present_total", "vk_load", "verify", "verify_total")
JWT_BYTES = {"1k": 1024, "1920": 1920, "2k": 2048, "4k": 4096, "8k": 8192}
JWT_MS = {"1k": 600.0, "1920": 950.0, "2k": 1000.0, "4k": 1900.0, "8k": 3800.0}
JWT_CONSTRAINTS = {"1k": 1_000_000, "1920": 1_900_000, "2k": 2_000_000, "4k": 4_000_000, "8k": 8_000_000}
PER_COMPRESSION = 29_900
# Policy cost model: a*M*N + b*M*beta + c*T*M + d*T^2 + e*M + f + g*T.
COEF = {"a": 300, "b": 40, "c": 120, "d": 25, "e": 2000, "f": 4444, "g": 100}
SIZES = {"2k_prepare_proving.key": 431_866_474, "2k_show_proving.key": 4_862_778,
         "2k_prepare_verifying.key": 431_866_442, "2k_show_verifying.key": 4_862_746,
         "prepared_state_bytes": {"instance": 20_000, "witness": 3_000_000, "blinds": 2_000},
         "presentation_bytes": 160_000, "footprint_bytes": 440_000_000}
CONFIGS = ("v1", "main", "issuer", "revocation", "combined")
POPULATIONS = (1024, 32768, 1_046_528)


def next_pow2(n):
    return 1 << (n - 1).bit_length()


def policy_constraints(n=2, m=2, t=8, beta=64):
    return (COEF["a"] * m * n + COEF["b"] * m * beta + COEF["c"] * t * m + COEF["d"] * t * t
            + COEF["e"] * m + COEF["f"] + COEF["g"] * t)


def show_constraints(d_iss=0, d_rev=0, n=2, m=2, t=8, beta=64):
    c = policy_constraints(n, m, t, beta)
    if d_iss:
        c += (2 * d_iss + 2) * PER_COMPRESSION
    if d_rev:
        c += (2 * d_rev + 3) * PER_COMPRESSION
    return c


def show_params(config, d_iss=0, d_rev=0, n=2, m=2, t=8, beta=64):
    base = [n, m, t, beta]
    return {"v1": None, "main": base, "issuer": base + [d_iss], "revocation": base + [d_rev],
            "combined": base + [d_iss, d_rev]}[config]


def step_ms(step, config, jwt, d_iss, d_rev):
    prep = JWT_MS[jwt] * {"v1": 0.97, "main": 1.0, "issuer": 1.01, "revocation": 1.01, "combined": 1.03, "variant": 1.03}[config]
    c = 17_500 if config == "v1" else show_constraints(d_iss, d_rev)
    show = 100 + next_pow2(c) / 2000
    return {"prepare_witness": prep * 0.5, "prepare_prove": prep, "prepare_reblind": prep * 0.9,
            "prepare_total": prep * 1.5, "show_prove": show, "show_reblind": 40.0,
            "present_total": prep * 0.9 + show + 40.0, "vk_load": 20.0, "verify": 60.0,
            "verify_total": 80.0, "vk_digest": 100.0, "key_load_prepare": 300.0, "key_load_show": 50.0, "statement_check": 5.0, "state_load": 30.0,
            "batch_reblind": prep * 0.9}[step]


def device(platform="macos", model="Mac15,9", **extra):
    d = {"kind": "DEVICE", "platform": platform, "product_model": model, "run_id": "r", "bench_sha": "bbbbbbb",
         "base_sha": "aaaaaaa", "spartan2_rev": "d687dbb", "command": "synthetic", "rayon_default_threads": 12}
    d.update(extra)
    return d


def iter_row(step, ms, i, threads=12, flow=None, **extra):
    row = {"kind": "ITER", "step": step, "wall_us": round(ms * 1000), "phase": "cold" if i == 0 else "warm",
           "iter": i, "threads": threads, "ok": True, "flow": flow or {}}
    row.update(extra)
    return row


def phone_proc(steps_ms, config=None, model="SM-S947U1", **dev):
    """One phone process; steps_ms maps step to a list of warm wall times in ms."""
    rows = [device("android", model, **dev)]
    if config:
        rows[0]["config"] = config
    for step, vals in steps_ms.items():
        rows += [iter_row(step, v, i, threads=8) for i, v in enumerate(vals, 1)]
    return rows


def mac_run(config, jwt="2k", d_iss=0, d_rev=0, issuers=0, revoked=0, passes=1, iters=5, cell=None,
            threads_requested=0, scale=1.0, matrix_id="A1", params=None, batch=None, sizes=None, path=None, **extra):
    """Rows of one cell: one process per pass, each with 1 cold and `iters` warm iterations."""
    cell = cell or f"{config}-{jwt}-{d_iss}-{d_rev}"
    path = path or ("generic" if matrix_id in ("S-D", "S-N", "S-MT") else "product")
    extra["path"] = path
    sp = params if params is not None else show_params(config, d_iss, d_rev)
    rows = []
    for p in range(passes):
        rows.append(device(config=config, cell=cell, matrix_id=matrix_id, jwt_size=jwt, d_iss=d_iss, d_rev=d_rev,
                           show_params=sp, issuers=issuers, revoked=revoked,
                           iss_path_len=min(d_iss, issuers.bit_length()) if d_iss else 0,
                           rev_path_len=min(d_rev, revoked.bit_length()) if d_rev else 0,
                           visit=p, **{"pass": p}, r1cs_present=False, power="ac", batch=batch,
                           threads_requested=threads_requested, **extra))
        rows.append({"kind": "SIZES", **(sizes or SIZES)})
        threads = threads_requested or 12
        for i in range(iters + 1):
            for s in STEPS:
                ms = step_ms(s, config, jwt, d_iss, d_rev) * scale * (1 + (i % 3 - 1) * 0.004)
                if path == "generic" and s == "show_prove":
                    ms *= 0.6          # a precomputed witness: the prove without witness generation
                if threads_requested == 1:
                    ms *= 5 if s in ("prepare_prove", "show_prove", "prepare_reblind", "present_total") else 1
                if batch and s == "prepare_reblind":
                    continue
                flow = {}
                if s == "present_total":
                    flow = {"prepare_proof_bytes": 112103, "show_proof_bytes": 47399 + (d_iss + d_rev) * 8}
                if s == "show_prove" and path == "product":
                    for name, share in (("show_witness", 0.4), ("show_prove_only", 0.6)):
                        rows.append(iter_row(name, ms * share, i, threads=threads))
                extra = {"vk_loaded": ["prepare", "show"]} if s == "vk_load" else {}
                row = iter_row(s, ms, i, threads=threads, flow=flow, **extra)
                if s in ("vk_load", "vk_digest", "state_load", "key_load_prepare", "key_load_show") and i == 0:
                    row["phase"] = "first"
                rows.append(row)
            if batch:
                rows.append(iter_row("batch_reblind", step_ms("batch_reblind", config, jwt, d_iss, d_rev) * batch * scale,
                                     i, threads=threads))
        rows.append({"kind": "DONE", "errors": 0})
    return rows


def shape_row(circuit, config, constraints, matrix_id="C0", params=None, jwt_size=None, d_iss=0, d_rev=0, **extra):
    padded = next_pow2(constraints)
    row = {"kind": "SHAPE", "circuit": circuit, "config": config, "matrix_id": matrix_id, "show_params": params,
           "jwt_size": jwt_size, "d_iss": d_iss, "d_rev": d_rev, "constraints": constraints,
           "wires": constraints + 100, "nnz_a": constraints * 2, "nnz_b": constraints * 2, "nnz_c": constraints,
           "padded_constraints": padded, "padded_vars": padded, "num_shared": 4, "num_precommitted": 2,
           "num_rest": 1, "r1cs_sha256": f"{circuit}-{constraints}", "loaded_constraints": constraints,
           "loaded_wires": constraints + 100, "commit": "ccccccc", "bench_sha": "bbbbbbb", "spartan2_rev": "d687dbb", "command": "synthetic"}
    row.update(extra)
    return row


def show_shape(config, d_iss=0, d_rev=0, n=2, m=2, t=8, beta=64, matrix_id="C0"):
    c = 17_500 if config == "v1" else show_constraints(d_iss, d_rev, n, m, t, beta)
    sp = show_params(config, d_iss, d_rev, n, m, t, beta)
    r = shape_row("show", config, c, matrix_id, sp, "2k", d_iss, d_rev)
    if sp:
        r.update(n_claims=n, m_pred=m, t_tok=t, beta=beta)
    return r


def shape_rows():
    rows = []
    for cfg in CONFIGS:
        di, dr = {"issuer": (8, 0), "revocation": (0, 10), "combined": (8, 10)}.get(cfg, (0, 0))
        for j, c in JWT_CONSTRAINTS.items():
            rows.append(shape_row(f"jwt_{j}", cfg, c + {"v1": -50_000, "main": 0}.get(cfg, 10_000),
                                  jwt_size=j, d_iss=di, d_rev=dr))
        rows.append(show_shape(cfg, di, dr))
        rows.append(shape_row("ecdsa", cfg, 9_000 if cfg == "v1" else 9_400, d_iss=di, d_rev=dr))
    rows.append(show_shape("combined", 8, 20))
    rows.append(shape_row("sha256", "main", PER_COMPRESSION, matrix_id="X2", compressions=1))
    for n in (8, 16, 32, 64):
        rows.append(show_shape("main", n=n, matrix_id="S-N"))
    for d in (8, 16, 24, 32):
        rows.append(show_shape("combined", 8, d, matrix_id="S-D"))
    for d in (16, 24, 32):
        rows.append(show_shape("combined", d, 20, matrix_id="S-D"))
    for m, t in ((1, 1), (4, 7), (8, 15), (16, 31)):
        rows.append(show_shape("main", m=m, t=t, matrix_id="S-MT"))
        rows.append(show_shape("combined", 8, 20, m=m, t=t, matrix_id="S-MT"))
    for n in (2, 8, 16, 32):
        for m in (1, 2, 4, 8, 16):
            for t in (1, 8, 15, 31):
                for beta in (16, 32, 64, 128):
                    rows.append(show_shape("main", n=n, m=m, t=t, beta=beta, matrix_id="X2"))
    return rows


def peakmem_rows():
    return [{"kind": "PEAKMEM", "config": cfg, "cell": cell, "phase": ph, "run": r,
             "max_rss_bytes": base + r * 1_000_000 + (i * 50_000_000),
             "peak_footprint_bytes": base + 5_000_000 + r * 1_000_000 + (i * 50_000_000), "wall_s": 3.0}
            for cfg, cell, base in (("main", "main-2k-0-0", 1_500_000_000), ("combined", "combined-2k-8-20", 3_100_000_000))
            for i, ph in enumerate(("prepare", "present", "verify", "online")) for r in range(3)]


def registry_rows():
    base_us = {"build": 9000, "insert": 80, "remove": 90, "revoke": 120, "revoke_many": 4000, "witness_member": 60,
               "witness_nonmember": 90, "root": 20, "refresh_incremental": 300, "refresh_rebuild": 9000,
               "export": 5000, "import": 7000}
    rows = []
    for reg in ("issuer", "revocation"):
        for pop in POPULATIONS:
            for op, us in base_us.items():
                for k in ((1, 100, 1000) if op.startswith("refresh") else (0,)):
                    for i in range(5):
                        rows.append({"kind": "REGISTRY", "registry": reg, "op": op, "population": pop, "k": k,
                                     "wall_us": round(us * (pop / 1024) ** 0.5 * max(k, 1) ** 0.3 * (1 + i * 0.01)),
                                     "iter": i + 1, "phase": "warm", "bytes": pop * 40, "node_version": "v22",
                                     "bench_sha": "ccccccc", "command": "synthetic", "spartan2_rev": "n/a:node",
                                     "gc_exposed": True})
    for reg in ("issuer", "revocation"):
        for pop in POPULATIONS:
            for method, k in (("mirror_upper", 1), ("mirror_upper", 100), ("mirror_upper", 1000), ("mirror_min", 100),
                              ("proof_fetch", 1)):
                rows.append({"kind": "REGISTRY", "registry": reg, "op": "bandwidth", "method": method, "population": pop,
                             "k": k, "wall_us": None, "iter": 0, "phase": "cold",
                             "bytes": {"mirror_upper": 80 * k, "mirror_min": 32 * k + 32}.get(method, 32 * pop.bit_length()),
                             "commit": "ccccccc", "command": "synthetic", "spartan2_rev": "n/a:node", "gc_exposed": True})
    return rows


def e2e_rows():
    out = []
    for target, model, platform in (("mac", "Mac15,9", "macos"), ("s26plus", "SM-S947U1", "android"),
                                    ("iphone17pro", "iPhone18,1", "ios")):
        for wl in ("import", "warm", "cold", "registry_update", "stale_root_retry", "refill"):
            base = {"import": 6e6, "warm": 1.3e6, "cold": 2.5e6, "registry_update": 1.5e6,
                    "stale_root_retry": 2.9e6, "refill": 4e6}[wl]
            for composed, scale in ((True, 1.0), (False, 1.04)):
                if target != "mac" and not composed:
                    continue
                half = base * scale / 2
                stages = [{"name": "a", "wall_us": half, "where": "node"},
                          {"name": "b", "wall_us": half, "where": "mac" if target == "mac" else "phone"}]
                if wl == "cold":
                    cold = base * scale
                    stages = [{"name": "key_load", "wall_us": cold * 0.3, "where": "phone"},
                              {"name": "state_load", "wall_us": cold * 0.1, "where": "phone"},
                              {"name": "registry_load", "wall_us": cold * 0.2, "where": "node"},
                              {"name": "present", "wall_us": cold * 0.4, "where": "phone"}]
                out.append({"kind": "E2E", "workload": wl, "config": "combined", "matrix_id": "E1",
                            "platform": platform, "product_model": model, "composed": composed,
                            "stages": stages, "total_us": base * scale, "bench_sha": "bbbbbbb", "command": "synthetic",
                            "spartan2_rev": "d687dbb", "gc_exposed": True})
    return out


def mac_rows():
    out = []
    for j in ("1k", "2k"):
        out += mac_run("v1", jwt=j)
        out += mac_run("main", jwt=j)
        out += mac_run("issuer", jwt=j, d_iss=8, issuers=200)
        out += mac_run("revocation", jwt=j, d_rev=10, revoked=5000)
        out += mac_run("combined", jwt=j, d_iss=8, d_rev=10, issuers=200, revoked=5000)
        out += mac_run("combined", jwt=j, d_iss=8, d_rev=20, issuers=200, revoked=5000, passes=2,
                       sizes={**SIZES, "batch_bytes": 0})
    out += mac_run("v1", jwt="4k") + mac_run("v1", jwt="8k")
    for j in ("4k", "8k"):
        out += mac_run("combined", jwt=j, d_iss=8, d_rev=20, issuers=200, revoked=5000, matrix_id="A2")
    out += mac_run("combined", jwt="1920", d_iss=8, d_rev=20, issuers=200, revoked=5000, matrix_id="A2",
                   path="generic")
    out += mac_run("variant", d_iss=8, d_rev=20, issuers=200, revoked=5000, matrix_id="S-N", cell="sn_show_n2",
                   params=[2, 2, 8, 64, 8, 20], population={"issuers": 200, "revoked": 5000})
    for d in (8, 16, 20, 24, 32):
        out += mac_run("combined", d_iss=8, d_rev=d, issuers=200, revoked=5000, matrix_id="S-D",
                       population={"issuers": 200, "revoked": 5000})
    for d in (16, 24, 32):
        out += mac_run("combined", d_iss=d, d_rev=20, issuers=200, revoked=5000, matrix_id="S-D")
    for pop in POPULATIONS:
        out += mac_run("combined", d_iss=8, d_rev=20, issuers=256, revoked=pop, matrix_id="S-P", cell=f"sp-{pop}",
                       population={"issuers": 256, "revoked": pop}, scale=1 + (pop % 7) * 0.001)
    for n in (2, 8, 16, 32):
        out += mac_run("main", matrix_id="S-N", cell=f"sn-{n}", params=show_params("main", n=n), n_claims=n)
    for m, t in ((1, 1), (2, 8), (4, 7), (8, 15), (16, 31)):
        out += mac_run("combined", d_iss=8, d_rev=20, matrix_id="S-MT", cell=f"smt-{m}-{t}",
                       params=show_params("combined", 8, 20, m=m, t=t), m_pred=m, t_tok=t)
    for b in (1, 8, 32, 128):
        out += mac_run("combined", d_iss=8, d_rev=20, matrix_id="S-B", cell=f"sb-{b}", batch=b,
                       sizes={**SIZES, "batch_bytes": 30_000 * b})
    out += mac_run("combined", d_iss=8, d_rev=20, matrix_id="X2", cell="x2-t1", threads_requested=1)
    out += mac_run("combined", d_iss=8, d_rev=20, matrix_id="X2", cell="x2-t1", threads_requested=0)
    return out


def bridge_rows():
    out = []
    for cfg, di, dr in (("main", 0, 0), ("combined", 8, 20)):
        out += mac_run(cfg, d_iss=di, d_rev=dr, issuers=200 if di else 0, revoked=5000 if dr else 0,
                       matrix_id="BR", cell=f"br-{cfg}", scale=1.03, harness="bench_host")
    return out


def as_phone(rows, model, platform, scale):
    """Turn Mac rows into phone rows: other platform and model, scaled times, a peak_kb probe."""
    out = []
    for r in rows:
        r = dict(r)
        if r["kind"] == "DEVICE":
            r.update(platform=platform, product_model=model, rayon_default_threads=8)
        elif r["kind"] == "ITER":
            if r["step"] == "vk_digest":
                continue
            if r["phase"] == "first":
                r["phase"] = "cold"
            r["wall_us"] = round(r["wall_us"] * scale)
            r["peak_kb"] = 2_000_000 if platform == "android" else 2_400_000
        out.append(r)
    return out


def phone_session(model, platform, scale, session_scale=1.0, iters=14):
    base = (mac_run("main", cell="main-2k", iters=iters, matrix_id="A1")
            + mac_run("combined", d_iss=8, d_rev=20, issuers=200, revoked=5000, cell="combined-2k", iters=iters,
                      matrix_id="A1"))
    return as_phone(base, model, platform, scale * session_scale)


def write_jsonl(path, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def write_root(root):
    write_jsonl(os.path.join(root, "laptop", "runs", "r1", "bench.jsonl"), mac_rows())
    write_jsonl(os.path.join(root, "laptop", "runs", "r1", "e2e.jsonl"), e2e_rows())
    write_jsonl(os.path.join(root, "laptop", "runs", "r2", "bench.jsonl"), bridge_rows())
    write_jsonl(os.path.join(root, "laptop", "peakmem.jsonl"), peakmem_rows())
    write_jsonl(os.path.join(root, "variants", "shape.jsonl"), shape_rows())
    write_jsonl(os.path.join(root, "registry", "registry.jsonl"), registry_rows())
    for dev, model, plat, scale in (("s26plus", "SM-S947U1", "android", 1.2),
                                    ("iphone17pro", "iPhone18,1", "ios", 0.9)):
        for s, sc in (("s1", 1.0), ("s2", 1.02), ("s3", 0.99)):
            rows = phone_session(model, plat, scale, sc)
            write_jsonl(os.path.join(root, "mobile", dev, "combined", s, "bench.jsonl"), rows)


def write_final_extras(root, matrices_dir):
    """Matrix files and PHONECHECK rows that make the synthetic root complete for `--final`."""
    from bench import Dataset
    ds = Dataset.load_root(root)
    cells = [{"id": c[3], "visits": 1, "cmd": "run"} for c in ds.cells() if c[0] == "mac" and not c[3].endswith("+t1")]
    os.makedirs(matrices_dir, exist_ok=True)
    with open(os.path.join(matrices_dir, "X.json"), "w") as f:
        json.dump({"matrix_id": "X", "cells": cells}, f)
    with open(os.path.join(matrices_dir, "PM.json"), "w") as f:
        json.dump({"matrix_id": "PM", "cells": [{"id": "PM-a", "cmd": "peakmem", "stage": "main/main-2k-0-0", "visits": 3,
                                                 "phases": ["prepare", "present", "verify", "online"]}]}, f)
    os.makedirs(os.path.join(root, "mobile"), exist_ok=True)
    with open(os.path.join(root, "mobile", "expected_sessions.json"), "w") as f:
        json.dump({"iphone17pro-26-5": {"main": 3, "combined": 3}, "m2q-36": {"main": 3, "combined": 3}}, f)
    write_jsonl(os.path.join(root, "phonecheck", "pc.jsonl"), [
        {"kind": "PHONECHECK", "device": dev, "config": cfg, "session": s, "proofs_valid": True, "linked": True,
         "roots_match_registry": True}
        for dev in ("s26plus", "iphone17pro") for cfg in ("main", "combined") for s in ("s1", "s2", "s3")])
