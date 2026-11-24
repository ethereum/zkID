"""Regenerates every table, figure, check and provenance row: analyze.py --root <bench dir> --out <dir>."""
import argparse
import os
import sys

from bench import Dataset
from checks import (Check, gate_gc, gate_peakmem, gate_phonecheck, gate_sessions, load_expected_sessions, gate_provenance, gate_visits, load_matrices, load_pm,
                    render_md, run_all)
from compose import compose
from figures import FIGURES, make_all
from labels import write_labels
from fits import DEPTH_CONFIGS, depth_rows, fit_cost_model, hash_count_check, per_compression, per_level
from provenance import Prov
from tables import REF_PARAMS, TABLES, Ctx, cost_rows, lint_tabular


DEFAULT_MATRICES = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "matrices")
ROOT_ENV = "OPENACPLUS_BENCH_ROOT"


def fits_md(ctx):
    ds = ctx.ds
    lines = ["# Fits", ""]
    for key, label in (("d_rev", "revocation depth at D_iss 8"), ("d_iss", "issuer depth at D_rev 20")):
        rows = depth_rows(ds, key)
        lines += [f"## Show constraints against {label}", "", "| padding class | slope per level | intercept | R^2 | n |", "|---|---|---|---|---|"]
        if len(rows) >= 2:
            for cls, f in per_level(rows, key)["fits"].items():
                lines.append(f"| {cls} | " + (f"{f.slope:.1f} | {f.intercept:.1f} | {f.r2:.6f} | {f.n} |" if f else "-- | -- | -- | 1 |"))
        lines.append("")
    pts = FIGURES["F1"](ctx)
    lines += ["## show_prove against depth, generic path, one population", "",
              "| tree | padding class | population | slope per level (ms) | intercept (ms) | R^2 |", "|---|---|---|---|---|---|"]
    lines += [f"| {r['tree']} | {r['padded']} | {r['population']} | {r['slope']:.2f} | {r['intercept']:.1f} | {r['r2']:.4f} |"
              for r in pts if r["kind"] == "fit_time"]
    lines.append("")
    pc = per_compression(ds)
    lines += ["## SHA-256", "", f"Standalone compression gadget: {pc if pc else '--'} constraints.", ""]
    try:
        rows = cost_rows(ctx)
        fit, flat = fit_cost_model(rows), fit_cost_model(rows, with_t=False)
        lines += ["## Eq. 11 cost model", "",
                  "constraints = a*M*N + b*M*beta + c*T*M + d*T^2 + e*M + f + g*T, M_D = 0", "",
                  "| term | with the linear T term | without the linear T term |", "|---|---|---|"]
        lines += [f"| {k} | {v:.2f} | " + (f"{flat.coef[k]:.2f}" if k in flat.coef else "--") + " |" for k, v in fit.coef.items()]
        lines += ["", f"With: R^2 = {fit.r2:.6f}, n = {fit.n}, largest residual = {max(abs(r) for r in fit.residuals):.2f}.",
                  f"Without the linear T term: R^2 = {flat.r2:.6f}, largest residual = {max(abs(r) for r in flat.residuals):.2f}.", ""]
    except (ValueError, ZeroDivisionError):
        lines += ["## Eq. 11 cost model", "", "Not enough shapes for a full-rank fit.", ""]
    hc = [r for r in hash_count_check(ds) if r["show_params"][:4] == REF_PARAMS and r.get("matrix_id") != "X2"]
    lines += ["## Registry hash count", "",
              "Structural compressions are 2*D_iss + 2 for the issuer tree and 2*D_rev + 3 for revocation, from the parameters. "
              "The paper's hashes, at two compressions each, give 2*(D_iss + D_rev + 3) for both trees. "
              "The one-compression gap is sha256(secret), which fits in one block. "
              "The evidence column is (Show - GP-only Show) / standalone gadget constraints.", "", "| D_iss | D_rev | structural compressions | constraint delta / gadget | paper hashes | paper compressions | difference |", "|---|---|---|---|---|---|---|"]
    lines += [f"| {r['d_iss']} | {r['d_rev']} | {r['measured']} | " + (f"{r['evidence']:.1f}" if r["evidence"] is not None else "--")
              + f" | {r['paper_hashes']} | {r['paper_compressions']} | {r['diff']:+d} |" for r in hc]
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=os.environ.get(ROOT_ENV), help=f"bench data directory; default ${ROOT_ENV}")
    ap.add_argument("--out", required=True)
    ap.add_argument("--final", action="store_true", help="a gate without data fails; exit 1 on any FAIL")
    ap.add_argument("--matrices", default=DEFAULT_MATRICES, help="matrix JSON files that give each cell's required visits")
    ap.add_argument("--sessions", help="expected phone sessions; default <root>/mobile/expected_sessions.json")
    ap.add_argument("--include-smoke", action="store_true", help="keep rows marked smoke")
    ap.add_argument("--drop-phone", type=int, default=2, help="warm iterations dropped per phone process")
    args = ap.parse_args(argv)
    if not args.root:
        ap.error(f"--root is required when {ROOT_ENV} is not set")
    os.makedirs(args.out, exist_ok=True)
    ds = Dataset.load_root(args.root, drop_warm={"phone": args.drop_phone}, include_smoke=args.include_smoke)
    compose(ds)
    ctx = Ctx(ds, Prov(ds))
    bad = 0
    for name, fn in TABLES.items():
        before = len(ctx.prov.rows)
        try:
            tex = fn(ctx)
        except Exception as ex:  # noqa: BLE001  (reported as a FAIL in checks.md)
            ctx.problems.append((name, f"table error: {type(ex).__name__}: {ex}", "error"))
            continue
        if len(ctx.prov.rows) == before:
            ctx.skipped.append(name)
        for e in lint_tabular(tex):
            print(f"{name}: {e}", file=sys.stderr)
            bad += 1
        with open(os.path.join(args.out, name + ".tex"), "w") as f:
            f.write(tex)
    make_all(ctx, args.out)
    checks = run_all(ds, final=args.final) + [Check("data", p[0], "fail", None, None, p[1]) for p in ctx.problems]
    if args.final:
        checks += (gate_visits(ds, load_matrices(args.matrices)) + gate_peakmem(ds, load_pm(args.matrices))
                   + gate_provenance(ctx.prov.rows) + gate_phonecheck(ds) + gate_gc(ds)
                   + gate_sessions(ds, load_expected_sessions(args.sessions or os.path.join(args.root, "mobile", "expected_sessions.json"))))
    bad += sum(1 for p in ctx.problems if len(p) > 2) + sum(1 for c in checks if c.detail.startswith("check error"))
    with open(os.path.join(args.out, "checks.md"), "w") as f:
        f.write(render_md(checks, ds, ctx.skipped, ctx.notes))
    try:
        text = fits_md(ctx)
    except Exception as ex:  # noqa: BLE001
        text = f"# Fits\n\nFailed: {type(ex).__name__}: {ex}\n"
        bad += 1
    with open(os.path.join(args.out, "fits.md"), "w") as f:
        f.write(text)
    ctx.prov.write(os.path.join(args.out, "provenance.csv"))
    write_labels(args.out)
    bad += sum(1 for c in checks if args.final and c.status == "fail")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
