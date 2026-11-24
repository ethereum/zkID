"""pgfplots source for F1-F6, one F<n>.tex per figure, from the same rows as F<n>.csv. \\input it inside a figure environment."""
import math

PANEL_WIDTH = r"0.38\linewidth"
PANEL_GAP = "2.2cm"
# One style per series name, so a config looks the same in every panel and figure.
STYLES = {"v1": "color=black, mark=triangle*", "main": "color=blue, mark=*", "combined": "color=red, mark=square*",
          "revocation": "color=orange, mark=diamond*", "issuer": "color=teal, mark=triangle*"}
CONFIG_NAMES = {"v1": "OpenAC v1.0.0", "main": "OpenAC+ GP only", "combined": "OpenAC+ (8,20)"}


def esc(text):
    for ch in "&%#_$":
        text = text.replace(ch, "\\" + ch)
    return text


def _num(v):
    return str(v) if isinstance(v, int) else f"{v:.6g}"


def _ok(v):
    return v is not None and math.isfinite(v)


def _series(label, pts, opts=""):
    """pts is [(x, y)]; pairs with a missing or non-finite number are left out."""
    pts = [(x, y) for x, y in pts if _ok(x) and _ok(y)]
    return (label, pts, opts) if pts else None


def _axis(series, xlabel, ylabel, extra="", name=None, after=None):
    opts = [f"width={PANEL_WIDTH}", "height=0.30\\linewidth", f"xlabel={{{xlabel}}}", f"ylabel={{{ylabel}}}",
            "legend style={at={(0.5,-0.32)}, anchor=north, font=\\scriptsize}", "legend cell align=left", "grid=major"]
    if extra:
        opts.append(extra)
    if name:
        opts.append(f"name={name}")
    if after:
        opts += [f"at={{({after}.east)}}", "anchor=west", f"xshift={PANEL_GAP}"]
    lines = ["  \\begin{axis}[", "    " + ",\n    ".join(opts) + "]"]
    for label, pts, plot_opts in series:
        coords = " ".join(f"({_num(x)},{_num(y)})" for x, y in pts)
        lines.append(f"    \\addplot{'[' + plot_opts + ']' if plot_opts else ''} coordinates {{{coords}}};")
        lines.append(f"    \\addlegendentry{{{esc(label)}}}")
    lines.append("  \\end{axis}")
    return lines


def _picture(panels):
    """panels is a list of (series, xlabel, ylabel, extra); the series are already filtered, empty panels are dropped."""
    panels = [p for p in panels if any(p[0])]
    lines = ["% requires \\usepackage{pgfplots}", "\\begin{tikzpicture}", "  \\pgfplotsset{compat=1.18}"]
    for i, (series, xlabel, ylabel, extra) in enumerate(panels):
        lines += _axis([s for s in series if s], xlabel, ylabel, extra, name=f"p{i}", after=f"p{i - 1}" if i else None)
    lines.append("\\end{tikzpicture}")
    return "\n".join(lines) + "\n"


def _cat_ticks(labels):
    return f"xtick={{{','.join(str(i) for i in range(len(labels)))}}},\n    xticklabels={{{','.join('{' + esc(str(l)) + '}' for l in labels)}}}"


def f1(rows):
    cons, time = [], []
    for tree in ("revocation", "issuer"):
        pts = [r for r in rows if r["kind"] == "point" and r["tree"] == tree]
        cons.append(_series(f"{tree} depth", [(r["depth"], r["constraints"]) for r in pts], STYLES[tree]))
        time.append(_series(f"{tree} depth", [(r["depth"], r["show_prove_ms"]) for r in pts], STYLES[tree]))
    for tree in ("revocation", "issuer"):
        prod = [r for r in rows if r["kind"] == "point_product" and r["tree"] == tree]
        time.append(_series(f"{tree}, product path (not fitted)", [(r["depth"], r["show_prove_ms"]) for r in prod],
                            STYLES[tree] + ", only marks, mark=x"))
    return _picture([(cons, "Registry depth D", "Show constraints", ""),
                     (time, "Registry depth D", "Show prove, witness precomputed (ms)", "")])


def f2(rows):
    s = _series("Show prove", [(r["path_len"], r["show_prove_ms"]) for r in rows])
    return _picture([([s], "Actual revocation path length", "Show prove, witness ready (ms)", "")])


def f3(rows):
    series = [_series(CONFIG_NAMES[cfg], [(r["bytes"], r["prepare_prove_ms"]) for r in sorted(rows, key=lambda r: r["bytes"]) if r["config"] == cfg],
                    STYLES[cfg])
              for cfg in ("v1", "main", "combined")]
    extra = ("xmode=log,\n    log basis x=2,\n    xtick={1024,2048,4096,8192},\n    xticklabels={1k,2k,4k,8k},\n"
             "    minor tick num=0")
    return _picture([(series, "Credential size (bytes)", "Prepare prove (ms)", extra)])


def _two_panel(rows, xcol, labels, xlabel):
    names = (("main", CONFIG_NAMES["main"]), ("combined", CONFIG_NAMES["combined"]))
    panels = []
    for ycol, ylabel in (("constraints", "Show constraints"), ("show_prove_ms", "Show prove, witness precomputed (ms)")):
        series = [_series(name, [(labels.index(r[xcol]), r[ycol]) for r in rows if r["config"] == cfg], STYLES[cfg]) for cfg, name in names]
        ys = [y for sr in series if sr for _, y in sr[1]]
        scale = "ymode=log" if ys and max(ys) >= 4 * min(ys) else "ymin=0"   # a log axis over a flat range overflows TeX
        panels.append((series, xlabel, ylabel, scale + ",\n    " + _cat_ticks(labels)))
    return _picture(panels)


def f4(rows):
    rows = [dict(r, mt=f"({r['m']},{r['t']})") for r in rows]
    labels = sorted({r["mt"] for r in rows}, key=lambda s: tuple(map(int, s.strip("()").split(","))))
    return _two_panel(rows, "mt", labels, "Predicate and token capacity (M,T)")


def f5(rows):
    return _two_panel(rows, "n", sorted({r["n"] for r in rows}), "Message capacity N")


F6_GROUPS = (("insert", "remove", "revoke", "witness_member", "witness_nonmember", "root", "path_verify", "root_recompute"),
             ("build", "export", "import", "refresh_incremental", "refresh_rebuild"))


def f6(rows):
    panels = []
    for ops in F6_GROUPS:
        series = []
        for op in ops:
            for method, k in sorted({(r["method"], r["k"]) for r in rows if r["op"] == op}):
                pts = sorted((r for r in rows if r["op"] == op and r["k"] == k and r["method"] == method), key=lambda r: r["population"])
                label = op.replace("_", " ") + (f" k={k}" if k else "") + (f" {method}" if method else "")
                series.append(_series(label, [(p["population"], p["median_ms"]) for p in pts]))
        panels.append((series, "Registry population", "Median time (ms)", "xmode=log,\n    log basis x=2,\n    ymode=log,\n    xtick=data"))
    return _picture(panels)


EMITTERS = {"F1": f1, "F2": f2, "F3": f3, "F4": f4, "F5": f5, "F6": f6}
