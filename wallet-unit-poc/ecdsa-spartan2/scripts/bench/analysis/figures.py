"""Figures F1-F6: a CSV, a PDF and a pgfplots .tex each, every plotted number recorded in provenance."""
import csv
import os
from collections import defaultdict

from bench import population, summarize
from fits import fit_by_class, padding_class
from pgf import EMITTERS

REF = [2, 2, 8, 64]
INK, MUTED, SURF, GRID = "#0b0b0b", "#52514e", "#fcfcfb", "#e4e3df"
COLORS = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
MARKERS = "osD^vp<>"
PRIVATE = ("_cells", "_rows", "_device", "_measures")


def _pt(row, cells=(), rows=(), device="mac", measures=""):
    return dict(row, _cells=list(cells), _rows=list(rows), _device=device, _measures=measures)


def _timed(ctx, cells_by_key):
    """key -> (summary, cell) for the cell with the most warm rows per key."""
    out = {}
    for key, cells in cells_by_key.items():
        best = max(cells, key=lambda c: len(ctx.ds.values(c, "show_prove")))
        s = ctx.ds.summary(best, "show_prove")
        if s:
            out[key] = (s, best)
    return out


def _meta_param(ctx, cell, name, index):
    m = ctx.ds.meta[cell]
    if m.get(name) is not None:
        return m[name]
    sp = m.get("show_params")
    return sp[index] if sp else None


def f1(ctx):
    """Show constraints and time against depth. Time points come from generic-path S-D cells only (a .wtns is precomputed);
    product-path points are a separate marked series and never enter a fit. Fits use one registry population."""
    shapes = [r for r in ctx.ds.shape_rows("show") if r.get("config") in ("combined", "variant")
              if r.get("show_params") and len(r["show_params"]) == 6 and r["show_params"][:4] == REF]
    trees = (("revocation", "d_rev", "d_iss", 8), ("issuer", "d_iss", "d_rev", 20))
    generic, product = defaultdict(list), defaultdict(list)
    for c in ctx.ds.cells():
        m = ctx.ds.meta[c]
        sp = m.get("show_params")
        if c[0] != "mac" or c[1] not in ("combined", "variant") or not sp or len(sp) != 6 or sp[:4] != REF:
            continue
        if m.get("path") == "generic":
            if c[2] == "S-D":
                generic[(m.get("d_iss"), m.get("d_rev"))].append(c)
        elif c[2] == "A1" and m.get("jwt_size") in (None, "2k"):
            product[(m.get("d_iss"), m.get("d_rev"))].append(c)
    out = []
    for tree, var, fixed, fv in trees:
        pts = {r[var]: r for r in shapes if r.get(fixed) == fv}
        series = []
        for depth in sorted(pts):
            r = pts[depth]
            key = (r["d_iss"], r["d_rev"])
            gt = _timed(ctx, {key: generic[key]}).get(key) if generic.get(key) else None
            s, cell = gt if gt else (None, None)
            series.append(_pt({"kind": "point", "tree": tree, "depth": depth, "path": "generic",
                               "population": population(ctx.ds.meta[cell])[1] if cell else None,
                               "constraints": r["constraints"], "padded": padding_class(r),
                               "show_prove_ms": s and s.median, "p25": s and s.p25, "p75": s and s.p75, "fitted": None},
                              cells=[cell] if cell else [], rows=[r],
                              measures="Show circuit constraints; Show prove only, precomputed witness (generic path)"))
            if product.get(key):
                ps, pc = _product_time(ctx, product[key])
                if ps:
                    out.append(_pt({"kind": "point_product", "tree": tree, "depth": depth, "path": "product",
                                    "population": population(ctx.ds.meta[pc])[1], "constraints": None, "padded": None,
                                    "show_prove_ms": ps.median, "p25": ps.p25, "p75": ps.p75, "fitted": False},
                                   cells=[pc], measures="Show prove without witness generation, product path; not fitted"))
        pops = [p["population"] for p in series if p["show_prove_ms"] is not None and p["population"] is not None]
        dominant = max(set(pops), key=pops.count) if pops else None
        for p in series:
            p["fitted"] = p["show_prove_ms"] is not None and p["population"] == dominant
        out += series
        for what, ycol in (("constraints", "constraints"), ("time", "show_prove_ms")):
            use = [p for p in series if p[ycol] is not None and (what == "constraints" or p["fitted"])]
            fits = fit_by_class([(p["depth"], p[ycol], p["padded"]) for p in use])
            for cls, f in fits.items():
                if f:
                    members = [p for p in use if p["padded"] == cls]
                    out.append(_pt({"kind": f"fit_{what}", "tree": tree, "padded": cls,
                                    "population": dominant if what == "time" else None,
                                    "slope": f.slope, "intercept": f.intercept, "r2": f.r2},
                                   cells=[c for p in members for c in p["_cells"]], rows=[r for p in members for r in p["_rows"]],
                                   measures=f"per-level slope and intercept of {what} inside one padding class"))
    return out


def _product_time(ctx, cells):
    best = max(cells, key=lambda c: len(ctx.ds.values(c, "show_prove_only") or ctx.ds.values(c, "show_prove")))
    step = "show_prove_only" if ctx.ds.values(best, "show_prove_only") else "show_prove"
    return ctx.ds.summary(best, step), best


def f2(ctx):
    out = []
    cells = [c for c in ctx.ds.cells() if c[0] == "mac" and c[2] == "S-P"]
    for c in sorted(cells, key=lambda c: population(ctx.ds.meta[c])[1] or 0):
        step = "show_prove_only" if ctx.ds.series.get(c + ("show_prove_only", "warm")) else "show_prove"
        s, m = ctx.ds.summary(c, step), ctx.ds.meta[c]
        if not s:
            continue
        if m.get("rev_path_len") is None:
            ctx.problems.append((c[3], "F2 needs rev_path_len on the DEVICE row; the point was dropped"))
            continue
        out.append(_pt({"revoked": population(m)[1], "path_len": m["rev_path_len"], "show_prove_ms": s.median,
                        "p25": s.p25, "p75": s.p75}, cells=[c],
                       measures=f"{step}: Show prove without witness generation (product) or prove only (generic), fixed (8,20) capacity"))
    return out


JWT_SIZES = {"1k": 1024, "1920": 1920, "2k": 2048, "4k": 4096, "8k": 8192}


def jwt_bytes(meta):
    """Credential size in bytes: jwt_params[0] when the row has it, else the size label."""
    params = meta.get("jwt_params")
    return params[0] if params else JWT_SIZES.get(meta.get("jwt_size"))


def f3(ctx):
    out = []
    by = defaultdict(list)
    for c in ctx.ds.cells():
        m = ctx.ds.meta[c]
        size, cfg = jwt_bytes(m), c[1]
        if c[0] != "mac" or c[2] not in ("A1", "A2") or size is None or cfg in ("issuer", "revocation"):
            continue
        if cfg == "variant":
            cfg = "combined"
            if m.get("d_rev") != 20 and c[2] != "A2":
                continue
        if cfg == "combined" and m.get("d_rev") != 20 and c[2] != "A2":
            continue
        by[(cfg, size)].append(c)
    for (cfg, size), cells in sorted(by.items()):
        best = max(cells, key=lambda c: len(ctx.ds.values(c, "prepare_prove")))
        s = ctx.ds.summary(best, "prepare_prove")
        if s:
            out.append(_pt({"config": cfg, "bytes": size, "prepare_prove_ms": s.median, "p25": s.p25, "p75": s.p75},
                           cells=[best], measures="Prepare proof alone, one credential"))
    return out


def f4(ctx):
    out = []
    for cfg, d in (("main", None), ("combined", (8, 20))):
        cands = ctx.ds.shape_rows("show", config=cfg) + (ctx.ds.shape_rows("show", config="variant") if d else [])
        for r in cands:
            sp = r.get("show_params")
            if not sp or r.get("matrix_id") not in ("S-MT", "C0") or sp[0] != 2 or sp[3] != 64:
                continue
            if d and (r.get("d_iss"), r.get("d_rev")) != d:
                continue
            out.append(_pt({"config": cfg, "m": sp[1], "t": sp[2], "constraints": r["constraints"], "show_prove_ms": None,
                            "p25": None, "p75": None}, rows=[r], measures="Show circuit constraints"))
    for c in ctx.ds.cells():
        if c[0] == "mac" and c[2] == "S-MT" and c[1] in ("combined", "variant") and ctx.ds.meta[c].get("path") != "product":
            s = ctx.ds.summary(c, "show_prove")
            mt = (_meta_param(ctx, c, "m_pred", 1), _meta_param(ctx, c, "t_tok", 2))
            for r in out:
                if s and r["config"] == "combined" and (r["m"], r["t"]) == mt:
                    r.update(show_prove_ms=s.median, p25=s.p25, p75=s.p75)
                    r["_cells"].append(c)
    return sorted(out, key=lambda r: (r["config"], r["m"], r["t"]))


def f5(ctx):
    out = []
    cands = [(r, "main") for r in ctx.ds.shape_rows("show", config="main")]
    cands += [(r, "combined") for r in ctx.ds.shape_rows("show") if r.get("config") in ("combined", "variant")
              and (r.get("d_iss"), r.get("d_rev")) == (8, 20)]
    seen = set()
    for r, cfg in cands:
        sp = r.get("show_params")
        if sp and r.get("matrix_id") in ("S-N", "C0") and sp[1:4] == REF[1:] and (cfg, sp[0]) not in seen:
            seen.add((cfg, sp[0]))
            out.append(_pt({"config": cfg, "n": sp[0], "constraints": r["constraints"], "show_prove_ms": None, "p25": None,
                            "p75": None}, rows=[r], measures="Show circuit constraints"))
    for c in ctx.ds.cells():
        if c[0] == "mac" and c[2] == "S-N" and ctx.ds.meta[c].get("path") != "product":
            cfg = "main" if c[1] == "main" else "combined"
            s, n = ctx.ds.summary(c, "show_prove"), _meta_param(ctx, c, "n_claims", 0)
            for r in out:
                if s and r["config"] == cfg and r["n"] == n:
                    r.update(show_prove_ms=s.median, p25=s.p25, p75=s.p75)
                    r["_cells"].append(c)
    return sorted(out, key=lambda r: (r["config"], r["n"]))


F6_OPS = ("insert", "remove", "revoke", "witness_member", "witness_nonmember", "root", "path_verify", "root_recompute", "build", "export", "import",
          "refresh_incremental", "refresh_rebuild")
F6_KS = {"refresh_incremental": (1, 100, 1000), "refresh_rebuild": (1000,)}


def f6(ctx):
    groups = defaultdict(list)
    for r in ctx.ds.registry:
        if r.get("registry") == "revocation" and r.get("wall_us") is not None and r.get("phase", "warm") == "warm":
            groups[(r["op"], r.get("method") or "", r.get("k") or 0, r["population"])].append(r)
    out = []
    for (op, method, k, pop), rs in sorted(groups.items()):
        if op not in F6_OPS or (op in F6_KS and k not in F6_KS[op]):
            continue
        s = summarize([r["wall_us"] / 1000 for r in rs])
        out.append(_pt({"op": op, "method": method, "k": k, "population": pop, "median_ms": s.median, "p25": s.p25, "p75": s.p75},
                       rows=rs, device="node", measures=f"one {op} on a revocation registry of {pop} entries"))
    return out


FIGURES = {"F1": f1, "F2": f2, "F3": f3, "F4": f4, "F5": f5, "F6": f6}
VALUE_COLS = {"F1": ("constraints", "padded", "show_prove_ms", "p25", "p75", "slope", "intercept", "r2"),
              "F2": ("show_prove_ms", "p25", "p75"), "F3": ("prepare_prove_ms", "p25", "p75"),
              "F4": ("constraints", "show_prove_ms", "p25", "p75"), "F5": ("constraints", "show_prove_ms", "p25", "p75"),
              "F6": ("median_ms", "p25", "p75")}
KEY_COLS = ("kind", "tree", "depth", "path", "population", "revoked", "config", "bytes", "m", "t", "n", "op", "method", "k", "population", "padded")


def _tag(name, row):
    parts = [str(row[k]) for k in KEY_COLS if k in row and row[k] is not None and k not in VALUE_COLS[name]]
    if "padded" in row and row.get("kind", "").startswith("fit"):
        parts.append(f"class{row['padded']}")
    return "/".join([name] + parts)


def write_csv(ctx, name, rows, outdir):
    cols = []
    for r in rows:
        for k in r:
            if k not in PRIVATE and k not in cols:
                cols.append(k)
    with open(os.path.join(outdir, name + ".csv"), "w", newline="") as f:
        w = csv.DictWriter(f, cols)
        w.writeheader()
        w.writerows({k: v for k, v in r.items() if k not in PRIVATE} for r in rows)
    for r in rows:
        for col in VALUE_COLS[name]:
            if r.get(col) is not None and not (col == "padded" and r.get("kind") == "point"):
                ctx.prov.add(f"{_tag(name, r)}|{col}", r[col], r["_device"], r["_measures"], cells=r["_cells"], rows=r["_rows"])


def _setup():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.size": 8, "axes.edgecolor": MUTED, "axes.labelcolor": INK, "text.color": INK,
                         "xtick.color": MUTED, "ytick.color": MUTED, "axes.facecolor": SURF, "figure.facecolor": SURF,
                         "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True,
                         "grid.color": GRID, "grid.linewidth": 0.6, "lines.linewidth": 1.6, "legend.frameon": False,
                         "pdf.fonttype": 42})
    return plt


def _save(fig, path):
    """No timestamps in the PDF, so two runs on the same rows give identical files."""
    fig.savefig(path, metadata={"CreationDate": None, "ModDate": None})


def _line(ax, i, label, xs, ys, lo=None, hi=None, label_end=True):
    c = COLORS[i % len(COLORS)]
    ax.plot(xs, ys, color=c, marker=MARKERS[i % len(MARKERS)], markersize=5, markeredgecolor=SURF,
            markeredgewidth=0.8, label=label, clip_on=False)
    if lo and hi:
        ax.vlines(xs, lo, hi, color=c, linewidth=1.0, alpha=0.7)
    if label_end and xs:
        ax.annotate(label, (xs[-1], ys[-1]), xytext=(5, 0), textcoords="offset points", color=INK, va="center", fontsize=7)


def plot_f1(plt, rows, path):
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 2.9))
    for ax, ycol, kind, ylab in ((axes[0], "constraints", "fit_constraints", "Show constraints"),
                                 (axes[1], "show_prove_ms", "fit_time", "show_prove: prove only, precomputed witness (ms)")):
        for i, tree in enumerate(("revocation", "issuer")):
            pts = [r for r in rows if r["kind"] == "point" and r["tree"] == tree and r[ycol] is not None]
            if not pts:
                continue
            _line(ax, i, f"{tree} depth", [p["depth"] for p in pts], [p[ycol] for p in pts],
                  [p["p25"] for p in pts] if ycol == "show_prove_ms" else None,
                  [p["p75"] for p in pts] if ycol == "show_prove_ms" else None, label_end=False)
            for fr in [r for r in rows if r["kind"] == kind and r["tree"] == tree]:
                cls = [p["depth"] for p in pts if p["padded"] == fr["padded"] and (ycol == "constraints" or p["fitted"])]
                if len(cls) > 1:
                    ax.plot(cls, [fr["intercept"] + fr["slope"] * x for x in cls], color=MUTED, linestyle="--", linewidth=0.9)
            if ycol == "show_prove_ms":
                prod = [r for r in rows if r["kind"] == "point_product" and r["tree"] == tree]
                if prod:
                    ax.plot([r["depth"] for r in prod], [r["show_prove_ms"] for r in prod], linestyle="none", marker="x",
                            color=COLORS[i], markersize=6, label=f"{tree}, product path (not fitted)")
        if ycol == "constraints":
            for cls in sorted({r["padded"] for r in rows if r["kind"] == "point"}):
                ax.axhline(cls, color=GRID, linestyle=":", linewidth=0.9, zorder=0)
                ax.annotate(f"$2^{{{cls.bit_length() - 1}}}$", (ax.get_xlim()[1], cls), xytext=(2, 0),
                            textcoords="offset points", fontsize=6, color=MUTED, va="center")
        ax.set_xlabel("Registry depth D")
        ax.set_ylabel(ylab)
        if ax.get_legend_handles_labels()[0]:
            ax.legend(loc="upper left", fontsize=6)
    fig.tight_layout()
    _save(fig, path)
    plt.close(fig)


def plot_f2(plt, rows, path):
    fig, ax = plt.subplots(figsize=(3.6, 2.8))
    xs = [r["path_len"] for r in rows]
    ax.errorbar(xs, [r["show_prove_ms"] for r in rows],
                yerr=[[r["show_prove_ms"] - r["p25"] for r in rows], [r["p75"] - r["show_prove_ms"] for r in rows]],
                color=COLORS[0], marker="o", markersize=5, capsize=2, linewidth=1.4)
    for r in rows:
        ax.annotate(f"{r['revoked']} revoked", (r["path_len"], r["show_prove_ms"]), xytext=(4, 6),
                    textcoords="offset points", fontsize=6.5, color=INK)
    ax.set_xlabel("Actual revocation path length")
    ax.set_ylabel("Show prove, witness ready (ms)")
    fig.tight_layout()
    _save(fig, path)
    plt.close(fig)


def plot_f3(plt, rows, path):
    fig, ax = plt.subplots(figsize=(3.6, 2.8))
    names = {"v1": "OpenAC v1.0.0", "main": "OpenAC+ GP only", "combined": "OpenAC+ (8,20)"}
    for i, cfg in enumerate(("v1", "main", "combined")):
        pts = sorted((r for r in rows if r["config"] == cfg), key=lambda r: r["bytes"])
        if pts:
            _line(ax, i, names[cfg], [p["bytes"] for p in pts], [p["prepare_prove_ms"] for p in pts],
                  [p["p25"] for p in pts], [p["p75"] for p in pts], label_end=False)
    ax.set_xscale("log", base=2)
    ax.set_xticks([1024, 1920, 2048, 4096, 8192])
    ax.set_xticklabels(["1k", "1920", "2k", "4k", "8k"], fontsize=6.5)
    ax.minorticks_off()
    ax.set_xlabel("Credential size (bytes)")
    ax.set_ylabel("prepare_prove (ms)")
    ax.legend(loc="upper left", fontsize=7)
    fig.tight_layout()
    _save(fig, path)
    plt.close(fig)


def _two_panel(plt, rows, path, xcol, xlabels, xlabel, series):
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 2.9))
    for ax, ycol, ylab in ((axes[0], "constraints", "Show constraints"), (axes[1], "show_prove_ms", "show_prove: prove only, precomputed witness (ms)")):
        for i, (label, sel) in enumerate(series):
            pts = [r for r in rows if sel(r) and r[ycol] is not None]
            if pts:
                _line(ax, i, label, [xlabels.index(r[xcol]) for r in pts], [r[ycol] for r in pts],
                      [r["p25"] for r in pts] if ycol == "show_prove_ms" else None,
                      [r["p75"] for r in pts] if ycol == "show_prove_ms" else None, label_end=False)
        ax.set_xticks(range(len(xlabels)))
        ax.set_xticklabels([str(x) for x in xlabels])
        ax.set_xlabel(xlabel)
        ax.set_ylabel(ylab)
        ax.set_yscale("log")
        if ax.get_legend_handles_labels()[0]:
            ax.legend(loc="upper left", fontsize=7)
    fig.tight_layout()
    _save(fig, path)
    plt.close(fig)


def plot_f4(plt, rows, path):
    for r in rows:
        r["mt"] = f"({r['m']},{r['t']})"
    labels = sorted({r["mt"] for r in rows}, key=lambda s: tuple(map(int, s.strip("()").split(","))))
    _two_panel(plt, rows, path, "mt", labels, "Predicate and token capacity (M,T)",
               [("OpenAC+ GP only", lambda r: r["config"] == "main"), ("OpenAC+ (8,20)", lambda r: r["config"] == "combined")])


def plot_f5(plt, rows, path):
    labels = sorted({r["n"] for r in rows})
    _two_panel(plt, rows, path, "n", labels, "Message capacity N",
               [("OpenAC+ GP only", lambda r: r["config"] == "main"), ("OpenAC+ (8,20)", lambda r: r["config"] == "combined")])


def plot_f6(plt, rows, path):
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 2.9), sharey=True)
    groups = (("Updates and witnesses", ("insert", "remove", "revoke", "witness_member", "witness_nonmember", "root", "path_verify", "root_recompute")),
              ("Bulk operations and refresh", ("build", "export", "import", "refresh_incremental", "refresh_rebuild")))
    for ax, (title, ops) in zip(axes, groups):
        i = 0
        for op in ops:
            for method, k in sorted({(r["method"], r["k"]) for r in rows if r["op"] == op}):
                pts = sorted((r for r in rows if r["op"] == op and r["k"] == k and r["method"] == method),
                             key=lambda r: r["population"])
                label = op.replace("_", " ") + (f" k={k}" if k else "") + (f" {method}" if method else "")
                _line(ax, i, label, [p["population"] for p in pts], [p["median_ms"] for p in pts], label_end=False)
                i += 1
        ax.set_xscale("log", base=2)
        ax.set_yscale("log")
        ax.set_title(title, fontsize=8, color=INK)
        ax.set_xlabel("Registry population")
        ax.legend(fontsize=6, loc="upper left")
    axes[0].set_ylabel("Median time (ms)")
    fig.tight_layout()
    _save(fig, path)
    plt.close(fig)


PLOTS = {"F1": plot_f1, "F2": plot_f2, "F3": plot_f3, "F4": plot_f4, "F5": plot_f5, "F6": plot_f6}


def make_all(ctx, outdir):
    """One figure failing is recorded in ctx.problems and does not stop the others."""
    os.makedirs(outdir, exist_ok=True)
    plt = _setup()
    made = []
    for name, fn in FIGURES.items():
        try:
            rows = fn(ctx)
            if not rows:
                ctx.skipped.append(name)
                continue
            write_csv(ctx, name, rows, outdir)
            public = [{k: v for k, v in r.items() if k not in PRIVATE} for r in rows]
            with open(os.path.join(outdir, name + ".tex"), "w") as f:
                f.write(EMITTERS[name](public))
            PLOTS[name](plt, public, os.path.join(outdir, name + ".pdf"))
            made.append(name)
        except Exception as e:  # noqa: BLE001  (reported as a FAIL in checks.md)
            ctx.problems.append((name, f"figure error: {type(e).__name__}: {e}", "error"))
            plt.close("all")
    return made
