"""LaTeX tabular fragments for the paper, one function per table, each number recorded in provenance."""
import math
import re
from collections import defaultdict

from bench import population, summarize
from checks import e2e_key, e2e_total
from compose import STATE_NOTE
from fits import DEPTH_CONFIGS, depth_rows, depth_slope_check, fit_cost_model, hash_count_check, per_compression, per_level
from provenance import Prov

DASH = "--"
GP, HEAD = "OpenAC+ GP only", "OpenAC+ (8,20)"
V1 = "OpenAC v1.0.0 (as published)"
CHAIN = [(V1, "v1", 0, 0), (GP, "main", 0, 0), ("+ issuer hiding", "issuer", 8, 0),
         ("+ revocation (10)", "revocation", 0, 10), ("OpenAC+ (8,10) as built", "combined", 8, 10),
         (HEAD, "combined", 8, 20)]
DEVICES = [("mac", "Mac"), ("iphone17pro", "iPhone 17 Pro"), ("s26plus", "Galaxy S26+")]
SIZES_JWT = [("1k", "1024 B"), ("1920", "1920 B"), ("2k", "2048 B"), ("4k", "4096 B"), ("8k", "8192 B")]
REF_PARAMS = [2, 2, 8, 64]


def fmt_time(ms):
    if ms is None:
        return DASH
    if ms < 0.5:
        return "<1 ms"
    return f"{ms / 1000:.1f} s" if ms >= 10000 else f"{round(ms)} ms"


def fmt_time_us(ms):
    """fmt_time for registry operations: values under 1 ms print as microseconds."""
    if ms is None or ms >= 1:
        return fmt_time(ms)
    us = ms * 1000
    return f"{us:.1f}\\,$\\mu$s" if us < 10 else f"{round(us)}\\,$\\mu$s"


def fmt_size(b):
    if b is None:
        return DASH
    if b >= 1e6:
        return f"{b / 1e6:.1f} MB"
    return f"{b / 1e3:.2f} kB" if b < 1000 else f"{b / 1e3:.1f} kB"


def fmt_int(n):
    return DASH if n is None else f"{round(n)}"


def fmt_stat(s):
    if s is None:
        return DASH
    if s.median >= 10000:
        return f"{s.median / 1000:.1f} s [{s.p25 / 1000:.1f}, {s.p75 / 1000:.1f}]"
    return f"{round(s.median)} ms [{round(s.p25)}, {round(s.p75)}]"


def tab(spec, header, body, mid_after_header=True):
    lines = [f"\\begin{{tabular}}{{{spec}}}", "\\toprule"]
    lines += header
    if mid_after_header:
        lines.append("\\midrule")
    lines += body
    lines += ["\\bottomrule", "\\end{tabular}", ""]
    return "\n".join(lines)


def row(*cells):
    return " & ".join(cells) + " \\\\"


def lint_tabular(tex):
    """Each row must have as many cells as the column spec; no TeX is installed, so count by hand."""
    errors = []
    for block in re.findall(r"\\begin\{tabular\}\{(.*?)\}\n(.*?)\\end\{tabular\}", tex, re.S):
        spec = re.sub(r"@\{[^}]*\}", "", block[0])
        spec = re.sub(r"p\{[^}]*\}", "p", spec)
        ncols = len(re.findall(r"[lcrp]", spec))
        for line in block[1].splitlines():
            if not line.endswith("\\\\"):
                continue
            body = line[:-2]
            cells = re.split(r"(?<!\\)&", body)
            n = 0
            for c in cells:
                m = re.search(r"\\multicolumn\{(\d+)\}", c)
                n += int(m.group(1)) if m else 1
            if n != ncols:
                errors.append(f"{n} cells, want {ncols}: {line}")
    return errors


def pow_label(n):
    p = math.log2(n)
    return f"$2^{{{int(p)}}}$" if p == int(p) else f"$\\approx 2^{{{round(p)}}}$"


class Ctx:
    def __init__(self, ds, prov=None):
        self.ds = ds
        self.prov = prov or Prov(ds)
        self.notes = []  # rows left out of a number, reported in checks.md
        self.skipped = []  # ids of tables and figures that had no rows
        self.problems = []  # (subject, detail): data a figure or table needed and did not find

    def pick(self, target, config, di=None, dr=None, matrix_id="A1", jwt="2k"):
        eq = {"jwt_size": jwt}
        if di is not None:
            eq["d_iss"] = di
        if dr is not None:
            eq["d_rev"] = dr
        return self.ds.pick(target, config, matrix_id, **eq)

    def stat(self, tag, cell, steps, measures, phase="warm"):
        """Median [p25, p75] text for a step or per-iteration sum of steps; records all three numbers."""
        if cell is None:
            return DASH
        s = self.ds.summary(cell, steps, phase)
        if s is None:
            return DASH
        for suffix, v in (("", s.median), ("|p25", s.p25), ("|p75", s.p75)):
            self.prov.add(tag + suffix, v, cell[0], measures, "ms", cells=[cell])
        return fmt_stat(s)

    def stat_first(self, tag, cell, step, measures, need_both_vks=False):
        """Median [p25, p75] of the first (Mac) or cold (phone) iteration of `step`, one row per visit."""
        if cell is None:
            return DASH
        phase = "first" if self.ds.series.get(cell + (step, "first")) else "cold"
        obs = self.ds.obs(cell, step, phase)
        if need_both_vks:
            kept = [o for o in obs if o.vk is not None and VK_BOTH <= set(o.vk)]
            if len(kept) < len(obs):
                self.notes.append(f"EXCLUDED {step} {'/'.join(cell)}: {len(obs) - len(kept)} of {len(obs)} rows "
                                  "do not say both VKs were loaded (`vk_loaded`)")
            obs = kept
        s = summarize([o.v for o in obs])
        if s is None:
            return DASH
        for suffix, v in (("", s.median), ("|p25", s.p25), ("|p75", s.p75)):
            self.prov.add(tag + suffix, v, cell[0], measures, "ms", cells=[cell])
        return fmt_stat(s)

    def value(self, tag, v, text, device, measures, unit="", cells=(), rows=()):
        if v is None:
            return DASH
        self.prov.add(tag, v, device, measures, unit, cells=cells, rows=rows)
        return text


PHASES = [
    ("Offline, per credential", ["prepare_witness", "prepare_prove"], "prepare_witness + prepare_prove, summed per iteration"),
    ("Per tuple", "prepare_reblind", "prepare_reblind of one prepared instance"),
    ("Online, tuple ready", ["show_prove", "show_reblind"], "show_prove + show_reblind, summed per iteration"),
    ("Online with refill", "present_total", "full presentation including the Prepare reblind"),
    ("Verify", "verify", "proof verification and linkage with the VKs in memory"),
    ("Statement check", "statement_check", "public-value, root and policy acceptance, timed outside verify"),
    ("Verify + acceptance", ["verify", "statement_check"], "verify + statement_check, summed per iteration"),
]
VK_BOTH = {"prepare", "show"}


def peak_bytes(ctx, cell):
    """Mac: largest median max RSS across phases. Phones: largest peak_kb over all steps."""
    if cell is None:
        return None, []
    if cell[0] != "mac":
        v = ctx.ds.peaks.get(cell)
        return (v or None), []
    rows = [r for r in ctx.ds.peakmem if r.get("config") == cell[1] and r.get("cell") == cell[3]]
    by = defaultdict(list)
    for r in rows:
        by[r["phase"]].append(r["max_rss_bytes"])
    if not by:
        return None, []
    return max(summarize(v).median for v in by.values()), rows


def t1(ctx):
    cols = []
    for target, _ in DEVICES:
        cols += [(target, ctx.pick(target, "main"), "gp"), (target, ctx.pick(target, "combined", dr=20), "head")]
    header = [row("", *[f"\\multicolumn{{2}}{{c}}{{{name}}}" for _, name in DEVICES]),
              "\\cmidrule(lr){2-3}\\cmidrule(lr){4-5}\\cmidrule(lr){6-7}",
              row("Phase", *[GP, HEAD] * 3)]
    body = []
    for label, steps, measures in PHASES:
        cells = [ctx.stat(f"T1/{label}/{t}/{k}", c, steps, measures) for t, c, k in cols]
        body.append(row(label, *cells))
    body.append(row("VK load, first iteration (Mac: page cache warm)", *[
        ctx.stat_first(f"T1/VK load/{t}/{k}", c, "vk_load",
                       "reading both VKs, first iteration, page cache warm" if t == "mac"
                       else "reading both VKs from storage, cold iteration", True)
        for t, c, k in cols]))
    body.append(row("VK digest (Mac only; the PR \\#115 sidecar removes it on phones)", *[
        ctx.stat(f"T1/VK digest/{t}/{k}", c if t == "mac" else None, "vk_digest",
                 "forcing the VK digest, which the phones restore from a sidecar")
        for t, c, k in cols]))
    cells = []
    for t, c, k in cols:
        v, rows = peak_bytes(ctx, c)
        cells.append(ctx.value(f"T1/Peak memory/{t}/{k}", v, fmt_size(v), t,
                               "peak resident memory over the whole flow", "bytes", cells=[c] if c else [], rows=rows))
    body.append(row("Peak memory", *cells))
    return tab("lrrrrrr", header, body)


def show_cells(ctx, tag, c):
    """Show prove with and without witness generation, as two cells."""
    return [ctx.stat(f"{tag}/show_prove", c, "show_prove", "Show prove including witness generation (product path)"),
            ctx.stat(f"{tag}/show_prove_only", c, "show_prove_only", "Show prove with the witness ready (product path)")]


def t1b(ctx):
    pairs = [("$P_0\\times S_0$", V1, "v1", 0, 0), ("$P_0\\times S_{GP}$", GP, "main", 0, 0),
             ("$P_{iss}\\times S_{GP+iss}$", "+ issuer hiding", "issuer", 8, 0), ("$P_+\\times S_+$", HEAD, "combined", 8, 20)]
    header = [row("Pair", "Configuration", "Prepare", "Show prove (incl. witness)", "Show prove (witness ready)", "Presentation",
                  "Verify", "Presentation vs GP only")]
    ref = ctx.pick("mac", "main", 0, 0)
    body = []
    for sym, label, cfg, di, dr in pairs:
        c = ctx.pick("mac", cfg, di, dr)
        tag = f"T1b/{label}"
        ratio = DASH
        a, b = (ctx.ds.summary(c, "present_total") if c else None), (ctx.ds.summary(ref, "present_total") if ref else None)
        if a and b:
            ratio = ctx.value(f"{tag}/ratio", a.median / b.median, f"{a.median / b.median:.2f}x", "mac",
                              "presentation median over the GP-only presentation median", "x", cells=[c, ref])
        body.append(row(sym, label,
                        ctx.stat(f"{tag}/prepare", c, ["prepare_witness", "prepare_prove"], "prepare_witness + prepare_prove, per credential"),
                        *show_cells(ctx, tag, c),
                        ctx.stat(f"{tag}/present_total", c, "present_total", "full presentation"),
                        ctx.stat(f"{tag}/verify", c, "verify", "proof verification and linkage, VKs in memory"), ratio))
    return tab("llrrrrrr", header, body)


def shape_for(ctx, circuit, config, **eq):
    """Prefer the C0 row, and for Show the reference parameters. `combined` also looks at generic-path `variant` rows."""
    rows = ctx.ds.shape_rows(circuit, config=config, **eq)
    if config == "combined":
        rows += ctx.ds.shape_rows(circuit, config="variant", **eq)
    if circuit == "show":
        rows = [r for r in rows if not r.get("show_params") or r["show_params"][:4] == REF_PARAMS]
    rows.sort(key=lambda r: (r.get("matrix_id") != "C0", r.get("config") != config))
    return rows[0] if rows else None


def nnz(r):
    return None if r is None or r.get("nnz_a") is None else r["nnz_a"] + r["nnz_b"] + r["nnz_c"]


JWT_BYTES = {"1k": 1024, "1920": 1920, "2k": 2048, "4k": 4096, "8k": 8192}


def jwt_shape(ctx, key, config):
    """The JWT shape row of a size: `jwt_<key>`, or the generic `jwt` circuit whose jwt_params[0] or jwt_size says so."""
    want = JWT_BYTES[key]
    rows = []
    for r in ctx.ds.shape_rows(None, config=config):
        c = r.get("circuit") or ""
        if not c.startswith("jwt"):
            continue
        params = r.get("jwt_params") or []
        if c == f"jwt_{key}" or (c == "jwt" and ((params and params[0] == want) or r.get("jwt_size") == key)):
            rows.append(r)
    rows.sort(key=lambda r: r.get("matrix_id") not in ("C0", "A2"))
    return rows[0] if rows else None


def t2a(ctx):
    cfgs = ["v1", "main", "issuer", "revocation", "combined"]
    header = [row("Credential", *cfgs)]
    body = []
    for key, label in SIZES_JWT:
        cells = []
        for cfg in cfgs:
            r = jwt_shape(ctx, key, cfg)
            cells.append(ctx.value(f"T2a/{key}/{cfg}", r and r["constraints"], fmt_int(r and r["constraints"]), "mac",
                                   "JWT (Prepare) circuit alone", "constraints", rows=[r] if r else []))
        body.append(row(label, *cells))
    return tab("lrrrrr", header, body)


def _levels(ctx, depth_key, value):
    rows = [dict(r, nnz=nnz(r)) for r in depth_rows(ctx.ds, depth_key)]
    return (per_level(rows, depth_key, value) if len(rows) >= 2 else None), rows


def t2b(ctx):
    base, ecdsa = shape_for(ctx, "show", "main"), shape_for(ctx, "ecdsa", "main")
    head = shape_for(ctx, "show", "combined", d_iss=8, d_rev=20)
    iss1, rev1 = shape_for(ctx, "show", "issuer", d_iss=8), shape_for(ctx, "show", "revocation", d_rev=10)
    header = [row("Component", "Constraints", "Non-zeros", "Padded size")]
    body = []

    def add(label, tag, c, n, p, rows, measures):
        body.append(row(label,
                        ctx.value(f"T2b/{tag}/constraints", c, fmt_int(c), "mac", measures, "constraints", rows=rows),
                        ctx.value(f"T2b/{tag}/nnz", n, fmt_int(n), "mac", measures, "entries", rows=rows),
                        ctx.value(f"T2b/{tag}/padded", p, fmt_int(p), "mac", measures, "constraints", rows=rows)))

    def sh(r, tag, label, measures):
        add(label, tag, r and r["constraints"], nnz(r), r and r.get("padded_constraints"), [r] if r else [], measures)

    sh(base, "base", "Base Show (GP only)", "Show circuit alone, no registries")
    if base and ecdsa:
        add("Predicates (Show $-$ ECDSA)", "predicates", base["constraints"] - ecdsa["constraints"],
            nnz(base) - nnz(ecdsa), None, [base, ecdsa], "Show minus ECDSA, GP-only config")
    else:
        add("Predicates (Show $-$ ECDSA)", "predicates", None, None, None, [], "")
    sh(ecdsa, "ecdsa", "ECDSA verification", "ECDSA circuit alone")
    ecdsa1 = shape_for(ctx, "ecdsa", "v1")
    if ecdsa and ecdsa1:
        add("ECDSA main $-$ v1 (device-binding hardening)", "hardening_ecdsa", ecdsa["constraints"] - ecdsa1["constraints"],
            nnz(ecdsa) - nnz(ecdsa1), None, [ecdsa, ecdsa1], "ECDSA circuit, main minus v1")
    else:
        add("ECDSA main $-$ v1 (device-binding hardening)", "hardening_ecdsa", None, None, None, [], "")
    jm, j1 = jwt_shape(ctx, "2k", "main"), jwt_shape(ctx, "2k", "v1")
    if jm and j1:
        add("Prepare main $-$ v1, 2048 B (all JWT-circuit changes v1.0.0 to main, including hardening and claim normalization)", "hardening_prepare",
            jm["constraints"] - j1["constraints"], nnz(jm) - nnz(j1), None, [jm, j1], "JWT circuit at 2k, main minus v1")
    else:
        add("Prepare main $-$ v1, 2048 B (all JWT-circuit changes v1.0.0 to main, including hardening and claim normalization)", "hardening_prepare", None, None, None, [], "")
    slopes = {}
    for key, label, one in (("d_iss", "Per issuer level", iss1), ("d_rev", "Per revocation level", rev1)):
        lv, rows = _levels(ctx, key, "constraints")
        ln, _ = _levels(ctx, key, "nnz")
        fc, fn = lv and lv["fit"], ln and ln["fit"]
        slopes[key] = (fc, fn)
        add(label, key, fc and fc.slope, fn and fn.slope, None, rows,
            "slope of the fit inside the largest padding class")
    for key, label, one, d in (("d_iss", "Issuer fixed part", iss1, 8), ("d_rev", "Revocation fixed part", rev1, 10)):
        fc, fn = slopes[key]
        if base and one and fc and fn:
            add(label, f"{key}_fixed", one["constraints"] - base["constraints"] - d * fc.slope,
                nnz(one) - nnz(base) - d * fn.slope, None, [one, base],
                f"{key.split('_')[1]}-only Show minus base minus depth times the per-level slope")
        else:
            add(label, f"{key}_fixed", None, None, None, [], "")
    sh(head, "headline", "Show at (8,20)", "full Show circuit of the headline config")
    return tab("lrrr", header, body)


def sizes_for(ctx, cell):
    return ctx.ds.sizes.get(cell, {}) if cell else {}


def prepared_parts(sz):
    ps = sz.get("prepared_state_bytes")
    if isinstance(ps, dict):
        return {k: ps.get(k) for k in ("instance", "witness", "blinds")}
    return {k: sz.get(f"prepared_state_bytes_{k}") for k in ("instance", "witness", "blinds")}


def t3(ctx):
    cells = [ctx.pick("mac", "main"), ctx.pick("mac", "combined", dr=20)]
    header = [row("Item", GP, HEAD)]
    items = [("Prepare proof", lambda c, s: ctx.ds.flow.get(c, {}).get("prepare_proof_bytes"), "proof"),
             ("Show proof", lambda c, s: ctx.ds.flow.get(c, {}).get("show_proof_bytes"), "proof"),
             ("Prepare proving key", lambda c, s: s.get(f"{ctx.ds.meta[c].get('jwt_size')}_prepare_proving.key"), "file"),
             ("Show proving key", lambda c, s: s.get(f"{ctx.ds.meta[c].get('jwt_size')}_show_proving.key"), "file"),
             ("Prepare verifying key", lambda c, s: s.get(f"{ctx.ds.meta[c].get('jwt_size')}_prepare_verifying.key"), "file"),
             ("Show verifying key", lambda c, s: s.get(f"{ctx.ds.meta[c].get('jwt_size')}_show_verifying.key"), "file")]
    for part in ("instance", "witness", "blinds"):
        items.append((f"Prepared state: {part}", lambda c, s, p=part: prepared_parts(s)[p], "state"))
    items += [("Presentation to the verifier", lambda c, s: s.get("presentation_bytes"), "everything the verifier receives"),
              ("On-device footprint per credential", lambda c, s: s.get("footprint_bytes"), "wallet storage per credential")]
    body = []
    for label, get, what in items:
        out = []
        for c, k in zip(cells, ("gp", "head")):
            v = get(c, sizes_for(ctx, c)) if c else None
            out.append(ctx.value(f"T3/{label}/{k}", v, fmt_size(v), "mac", f"{label}: size on disk or on the wire ({what})",
                                 "bytes", cells=[c] if c else []))
        body.append(row(label, *out))
    return tab("lrr", header, body)


def t4(ctx):
    header = [row("Configuration", "Show constraints", "Show prove (incl. witness)", "Show prove (witness ready)",
                  "Presentation", "Verify", "Proof bytes")]
    body = []
    for label, cfg, di, dr in CHAIN:
        c = ctx.pick("mac", cfg, di, dr)
        sh = shape_for(ctx, "show", cfg, d_iss=di, d_rev=dr)
        tag = f"T4/{label}"
        con = ctx.value(f"{tag}/constraints", sh and sh["constraints"], fmt_int(sh and sh["constraints"]), "mac",
                        "Show circuit alone", "constraints", rows=[sh] if sh else [])
        fl = ctx.ds.flow.get(c, {}) if c else {}
        pb = (fl["prepare_proof_bytes"] + fl["show_proof_bytes"]) if {"prepare_proof_bytes", "show_proof_bytes"} <= set(fl) else None
        body.append(row(label, con,
                        ctx.stat(f"{tag}/show_prove", c, "show_prove", "Show prove including witness generation, at 2k"),
                        ctx.stat(f"{tag}/show_prove_only", c, "show_prove_only", "Show prove with the witness ready, at 2k"),
                        ctx.stat(f"{tag}/present_total", c, "present_total", "full presentation, at 2k"),
                        ctx.stat(f"{tag}/verify", c, "verify", "proof verification and linkage, VKs in memory, at 2k"),
                        ctx.value(f"{tag}/proof_bytes", pb, fmt_size(pb), "mac", "Prepare plus Show proof bytes", "bytes",
                                  cells=[c] if c else [])))
    return tab("lrrrrrr", header, body)


def pop_cols(ctx):
    return sorted({r["population"] for r in ctx.ds.registry})


def method_label(method):
    return f" ({method})" if method else ""


def t5(ctx):
    pops = pop_cols(ctx)
    header = [row("Registry and operation", *[pow_label(p) for p in pops])] if pops else [row("Registry and operation", DASH)]
    groups = defaultdict(list)
    for r in ctx.ds.registry:
        if r.get("op") != "bandwidth" and r.get("wall_us") is not None and r.get("phase", "warm") == "warm":
            groups[(r["registry"], r["op"], r.get("method") or "", r.get("k") or 0, r["population"])].append(r)
    keys = sorted({k[:4] for k in groups}, key=str)
    body = []
    for reg, op, method, k in keys:
        label = f"{reg}: {op.replace('_', ' ')}" + (f" after {k}" if k else "") + method_label(method)
        cells = []
        for p in pops:
            rs = groups.get((reg, op, method, k, p))
            s = summarize([r["wall_us"] / 1000 for r in rs]) if rs else None
            cells.append(ctx.value(f"T5/{reg}/{op}/{method}/{k}/{p}", s and s.median, fmt_time_us(s and s.median), "node",
                                   f"one {op} on a registry of {p} entries", "ms", rows=rs or []))
        body.append(row(label, *cells))
        sizes = {p: groups[(reg, op, method, k, p)][0].get("bytes") for p in pops if (reg, op, method, k, p) in groups}
        if op in ("export", "import") and any(sizes.values()):
            body.append(row(f"{reg}: {op} size{method_label(method)}", *[
                ctx.value(f"T5/{reg}/{op}/{method}/{k}/{p}/bytes", sizes.get(p), fmt_size(sizes.get(p)), "node",
                          f"snapshot bytes of a {p}-entry registry", "bytes", rows=groups.get((reg, op, method, k, p), [])[:1])
                for p in pops]))
    return tab("l" + "r" * max(len(pops), 1), header, body)


BW_METHODS = {"mirror": "mirror_upper"}


def t5b(ctx):
    """Bytes per update for the mirror models and bytes per proof for proof_fetch."""
    rows = [dict(r, method=BW_METHODS.get(r.get("method"), r.get("method")))
            for r in ctx.ds.registry if r.get("op") == "bandwidth" and r.get("bytes") is not None]
    pops = sorted({r["population"] for r in rows})
    header = [row("Registry and method", *[pow_label(p) for p in pops])] if pops else [row("Registry and method", DASH)]
    groups = defaultdict(list)
    for r in rows:
        groups[(r["registry"], r["method"], r.get("k") or 0, r["population"])].append(r)
    body = []
    for reg, method, k in sorted({g[:3] for g in groups}, key=str):
        per_update = method != "proof_fetch"
        label = {"mirror_upper": f"{reg}: mirror, upper bound, per update at {k} updates",
                 "mirror_min": f"{reg}: mirror, minimum, per update at {k} updates",
                 "proof_fetch": f"{reg}: proof fetch, per proof after {k} updates"}.get(method, f"{reg}: {method}, k={k}")
        cells = []
        for p in pops:
            rs = groups.get((reg, method, k, p))
            vals = [r["bytes"] / (k if per_update and k else 1) for r in rs] if rs else []
            s = summarize(vals)
            what = {"mirror_upper": "changed leaf records plus root, an upper bound",
                    "mirror_min": "k*32 + 32 bytes, the minimum",
                    "proof_fetch": "one downloaded path"}.get(method, method)
            cells.append(ctx.value(f"T5b/{reg}/{method}/{k}/{p}", s and s.median, fmt_size(s and s.median), "node",
                                   f"bandwidth: {what}" + (", divided by k" if per_update else ""), "bytes", rows=rs or []))
        body.append(row(label, *cells))
    return tab("l" + "r" * max(len(pops), 1), header, body)


COLD_STAGES = ["key_load", "key_load_prepare", "key_load_show", "state_load", "vk_load", "vk_digest", "registry_load"]
E2E_ORDER = ["import", "warm", "cold", "registry_update", "stale_root_retry", "refill"]
REGISTRY_WORKLOADS = ("registry_update", "stale_root_retry")
MAC_WARM = ("key_load", "key_load_prepare", "key_load_show", "state_load", "vk_load")


def variant_label(v):
    workload, k, pop, batch, config = v
    label = workload.replace("_", " ")
    if workload in REGISTRY_WORKLOADS:
        label += (f", k={k}" if k else "") + (f", {pow_label(pop)}" if pop else "")
    if batch:
        label += f", B={batch}"
    if config not in (None, "combined"):
        label += f", {config}"
    return label


def t6(ctx):
    """Rows are grouped by workload, k, population, batch and config; nothing is pooled across them."""
    cols = [("mac", True, "Mac composed"), ("mac", False, "Mac orchestrated"), ("iphone17pro", True, "iPhone 17 Pro"),
            ("s26plus", True, "Galaxy S26+")]
    header = [row("Workload", *[c[2] for c in cols])]
    groups = defaultdict(list)
    for r in ctx.ds.e2e:
        t, config, wl, k, pop, batch = e2e_key(r)
        groups[((wl, k, pop, batch, config), t, bool(r.get("composed")))].append(r)
    variants = {g[0] for g in groups}
    seen = {v[0] for v in variants}
    variants |= {(wl, 0, None, None, None) for wl in E2E_ORDER if wl not in seen}
    order = lambda v: (E2E_ORDER.index(v[0]) if v[0] in E2E_ORDER else len(E2E_ORDER), v[1], v[2] or 0, v[3] or 0, str(v[4]))
    body = []
    for v in sorted(variants, key=order):
        out = []
        for target, composed, _ in cols:
            rs = groups.get((v, target, composed), [])
            s = summarize([e2e_total(r) / 1000 for r in rs if e2e_total(r)])
            out.append(ctx.value(f"T6/{variant_label(v)}/{target}/{'composed' if composed else 'orchestrated'}", s and s.median,
                                 fmt_time(s and s.median), target,
                                 "composed: steps measured separately and summed; the total includes verify and statement_check"
                                 if composed else "orchestrated: one end-to-end run", "ms", rows=rs))
        in_memory = v[0] == "cold" and any(r.get("state_in_memory") for (g, _, _), rs in groups.items() if g == v for r in rs)
        body.append(row(variant_label(v) + (f" ({STATE_NOTE})" if in_memory else ""), *out))
        if v[0] == "cold":
            for stage in COLD_STAGES:
                out = []
                for target, composed, _ in cols:
                    rs = groups.get((v, target, composed), [])
                    m = summarize([s["wall_us"] / 1000 for r in rs for s in r.get("stages", []) if s["name"] == stage])
                    out.append(ctx.value(f"T6/{variant_label(v)}/{stage}/{target}/{'composed' if composed else 'orchestrated'}",
                                         m and m.median, fmt_time(m and m.median), target,
                                         f"{stage} stage of the cold presentation", "ms", rows=rs))
                if any(c != DASH for c in out):
                    note = " (Mac: page-cache warm)" if stage in MAC_WARM else ""
                    body.append(row(f"cold: {stage.replace('_', ' ')}{note}", *out))
    return tab("lrrrr", header, body)


def base_cell(ctx, c):
    """The default-thread cell for a single-thread cell: `base_cell` from the row, else the A1 cell of the same circuit."""
    m = ctx.ds.meta[c]
    name = m.get("base_cell")
    if name:
        hits = [x for x in ctx.ds.cells() if x[0] == c[0] and x[3] == name]
        if hits:
            return hits[0]
    return ctx.ds.pick(c[0], c[1], "A1", jwt_size=m.get("jwt_size"), d_iss=m.get("d_iss"), d_rev=m.get("d_rev"))


def t7(ctx):
    header = [row("Configuration", "Step", "Default threads", "One thread", "Slowdown")]
    body = []
    for c in ctx.ds.cells():
        if c[0] != "mac" or not c[3].endswith("+t1"):
            continue
        base = base_cell(ctx, c)
        if base is None:
            continue
        for step in ("prepare_prove", "show_prove", "present_total", "verify"):
            a, b = ctx.ds.summary(base, step), ctx.ds.summary(c, step)
            tag = f"T7/{c[3]}/{step}"
            if not a or not b:
                continue
            body.append(row(f"{c[1]} {c[3][:-3]}", step.replace("_", " "),
                            ctx.stat(f"{tag}/default", base, step, f"{step} at the default thread count"),
                            ctx.stat(f"{tag}/t1", c, step, f"{step} with one thread"),
                            ctx.value(f"{tag}/ratio", b.median / a.median, f"{b.median / a.median:.1f}x", "mac",
                                      "one-thread median over default-thread median", "x", cells=[base, c])))
    return tab("llrrr", header, body or [row(DASH, DASH, DASH, DASH, DASH)])


def t8(ctx):
    header = [row("B", "B reblinds", "Per tuple", "Bytes per tuple")]
    cells = sorted((c for c in ctx.ds.cells() if c[2] == "S-B"), key=lambda c: ctx.ds.meta[c].get("batch") or 0)
    body = []
    for c in cells:
        b = ctx.ds.meta[c].get("batch")
        s = ctx.ds.summary(c, "batch_reblind")
        if not b or not s:
            continue
        tag = f"T8/{b}"
        total = ctx.stat(f"{tag}/total", c, "batch_reblind", f"batch_reblind wall time for {b} reblinds of one prepared instance")
        per = ctx.value(f"{tag}/per_tuple", s.median / b, fmt_time(s.median / b), "mac", "batch time divided by B", "ms", cells=[c])
        nb = ctx.ds.sizes.get(c, {}).get("batch_bytes")
        pb = nb / b if nb else None
        body.append(row(str(b), total, per, ctx.value(f"{tag}/bytes", pb, fmt_size(pb), "mac",
                                                      "batch bytes divided by B", "bytes", cells=[c])))
    return tab("rrrr", header, body or [row(DASH, DASH, DASH, DASH)])


def cost_rows(ctx):
    """Show shapes for the eq. 11 fit: the X2 grid at one (D_iss, D_rev) tail, else the GP-only shapes."""
    shows = [r for r in ctx.ds.shape_rows("show") if r.get("show_params")]
    grid = [r for r in shows if r.get("matrix_id") == "X2"]
    if grid:
        tails = defaultdict(int)
        for r in grid:
            tails[tuple(r["show_params"][4:])] += 1
        tail = max(tails, key=tails.get)
        shows = [r for r in grid if tuple(r["show_params"][4:]) == tail]
    else:
        shows = [r for r in shows if r.get("config") == "main"]
    seen = {}
    for r in shows:
        sp = r["show_params"]
        n, m, t, beta = (r.get("n_claims") or sp[0], r.get("m_pred") or sp[1], r.get("t_tok") or sp[2], r.get("beta") or sp[3])
        seen[(n, m, t, beta)] = {"n_claims": n, "m_pred": m, "t_tok": t, "beta": beta, "constraints": r["constraints"], "_row": r}
    return list(seen.values())


def t9a(ctx):
    header = [row("Term", "With linear $T$", "Without")]
    rows = cost_rows(ctx)
    try:
        fit, flat = fit_cost_model(rows), fit_cost_model(rows, with_t=False)
    except (ValueError, ZeroDivisionError):
        return tab("lrr", header, [row("fit", DASH, DASH)])
    src = [r["_row"] for r in rows]
    names = {"a": "$M N$", "b": "$M\\beta$", "c": "$T M$", "d": "$T^2$", "e": "$M$ (attribute-name hashing)",
             "f": "constant", "g": "$T$"}
    body = []
    for k in fit.coef:
        v = fit.coef[k]
        w = flat.coef.get(k)
        body.append(row(names[k], ctx.value(f"T9a/{k}", v, f"{v:.1f}", "mac",
                                            "least-squares coefficient of eq. 11 plus linear M and T terms", "constraints", rows=src),
                        ctx.value(f"T9a/{k}|without_t", w, f"{w:.1f}" if w is not None else DASH, "mac",
                                  "the same fit without the linear T term", "constraints", rows=src)))
    for key, label, a, b in (("r2", "$R^2$", fit.r2, flat.r2),
                             ("max_residual", "Largest residual", max(abs(r) for r in fit.residuals), max(abs(r) for r in flat.residuals))):
        fa, fb = (f"{a:.6f}", f"{b:.6f}") if key == "r2" else (f"{a:.1f}", f"{b:.1f}")
        body.append(row(label, ctx.value(f"T9a/{key}", a, fa, "mac", "goodness of the cost-model fit", "", rows=src),
                        ctx.value(f"T9a/{key}|without_t", b, fb, "mac", "goodness of the fit without the linear T term", "", rows=src)))
    body.append(row("Shapes fitted", ctx.value("T9a/n", fit.n, str(fit.n), "mac", "number of compiled Show shapes", "", rows=src), ""))
    return tab("lrr", header, body)


def t9b(ctx):
    header = [row("Config", "$D_{iss}$", "$D_{rev}$", "Compressions (structural)", "Constraint delta / gadget",
                  "Paper hashes", "Paper compressions", "Difference")]
    pc = per_compression(ctx.ds)
    body = []
    for r in hash_count_check(ctx.ds):
        if r["show_params"][:4] != REF_PARAMS or r.get("matrix_id") == "X2":
            continue
        tag = f"T9b/{r['config']}/{r['d_iss']}/{r['d_rev']}"
        src = [r["row"]]
        body.append(row(r["config"], str(r["d_iss"]), str(r["d_rev"]),
                        ctx.value(f"{tag}/measured", r["measured"], str(r["measured"]), "mac",
                                  "2*D_iss + 2 for the issuer tree plus 2*D_rev + 3 for revocation, from the parameters",
                                  "compressions", rows=src),
                        ctx.value(f"{tag}/evidence", r["evidence"], f"{r['evidence']:.1f}" if r["evidence"] is not None else DASH,
                                  "mac", f"(Show minus GP-only Show) / {pc} constraints per compression", "compressions", rows=src),
                        str(r["paper_hashes"]), str(r["paper_compressions"]),
                        ctx.value(f"{tag}/diff", r["diff"], f"{r['diff']:+d}", "mac",
                                  "structural count minus two compressions per paper hash; the gap is sha256(secret), one block",
                                  "compressions", rows=src)))
    for d in depth_slope_check(ctx.ds):
        tag = f"T9b/per_level/{d['tree']}"
        body.append(row(f"per {d['tree']} level", "", "", "2",
                        ctx.value(f"{tag}/compressions", d["compressions_per_level"], f"{d['compressions_per_level']:.2f}", "mac",
                                  "fitted constraints per level divided by constraints per compression", "compressions", rows=d["rows"]),
                        "1", "2", ""))
    if pc:
        body.append(row("SHA-256 gadget (constraints)", "", "", "",
                        ctx.value("T9b/gadget", pc, fmt_int(pc), "mac", "standalone SHA-256 compression circuit",
                                  "constraints", rows=ctx.ds.shape_rows("sha256")), "", "", ""))
    return tab("lrrrrrrr", header, body or [row(DASH, *[DASH] * 7)])


TABLES = {"T1": t1, "T1b": t1b, "T2a": t2a, "T2b": t2b, "T3": t3, "T4": t4, "T5": t5, "T5b": t5b, "T6": t6, "T7": t7,
          "T8": t8, "T9a": t9a, "T9b": t9b}
