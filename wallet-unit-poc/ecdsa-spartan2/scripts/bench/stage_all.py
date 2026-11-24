#!/usr/bin/env python3
"""Stage every product cell of the matrices (A1, A2, S-P, S-B, W, X2 single-thread, L5) with the current binaries.

Inputs: each worktree's circom/inputs for v1..combined; the headline inputs and inputs.jsonl for the
headline cells (roots from the registry). Generic cells are staged separately with layout.py and stage.py generic.
"""
import argparse
import json
import os
import subprocess
import sys

import stagelib as sl

HERE = os.path.dirname(os.path.abspath(__file__))
DEPTHS = {"v1": (0, 0), "main": (0, 0), "issuer": (8, 0), "revocation": (0, 10), "combined": (8, 10), "headline": (8, 20)}


# Chain inputs come from generate-inputs.ts: one issuer in the issuer registry, five revoked commitments.
CHAIN_POPULATION = {"v1": None, "main": None, "issuer": {"issuers": 1, "revoked": 0}, "revocation": {"issuers": 0, "revoked": 5},
                    "combined": {"issuers": 1, "revoked": 5}}


def run(args):
    r = subprocess.run([sys.executable, os.path.join(HERE, "stage.py"), "product", *args], capture_output=True, text=True)
    print(r.stderr.strip().splitlines()[-1] if r.stderr.strip() else r.returncode, file=sys.stderr)
    if r.returncode:
        sys.exit(r.stderr[-500:])


def chain_cells():
    for cfg in DEPTHS:
        if cfg == "headline":
            continue
        for size in ("1k", "2k"):
            yield cfg, f"A1-{cfg}-{size}", size, "A1"
    for cfg in ("v1", "combined"):
        for size in ("4k", "8k"):
            yield cfg, f"A2-{cfg}-{size}", size, "A2"


def chain_cells_all():
    yield from chain_cells()
    for cfg in ("main", "v1"):
        yield cfg, f"X2-{cfg}-1t", "2k", "X2"


def cell_meta(cell):
    """Single-thread cells name the default-thread cell they pair with."""
    return ["--meta", json.dumps({"base_cell": f"A1-{cell.split('-')[1]}-2k"})] if cell.startswith("X2-") else []


def stage_chain(only=None):
    for cfg, cell, size, mid in chain_cells_all():
        if only and cell not in only:
            continue
        w = sl.require_worktree(cfg)
        inp = os.path.join(w, "wallet-unit-poc/circom/inputs")
        di, dr = DEPTHS[cfg]
        run(["--worktree", w, "--config", cfg, "--cell", cell, "--size", size, "--matrix-id", mid, "--d-iss", str(di), "--d-rev", str(dr),
             "--jwt-input", f"{inp}/jwt/{size}/default.json", "--show-input", f"{inp}/show/{size}/default.json",
             *(["--population", json.dumps(CHAIN_POPULATION[cfg])] if CHAIN_POPULATION[cfg] else []), *cell_meta(cell)])


def headline(cell, mid, size, jwt, show, roots, meta=None, extra=(), only=None):
    if only and cell not in only:
        return
    run(["--worktree", sl.require_worktree("headline"), "--config", "headline", "--label-config", "combined", "--cell", cell, "--size", size, "--matrix-id", mid,
         "--d-iss", "8", "--d-rev", "20", "--jwt-input", jwt, "--show-input", show, "--roots", roots, *( ["--meta", json.dumps(meta)] if meta else []), *extra])


def stage_headline(only=None):
    def headline_(*a, **k):
        return headline(*a, only=only, **k)

    v = os.path.join(sl.bench_root(), "variants")
    own = os.path.join(sl.laptop_root(), "inputs/headline")
    headline_("A1-headline-1k", "A1", "1k", f"{own}/show-1k.jwt.json", f"{own}/show-1k.json", f"{own}/show-1k.roots.json")
    jwt, show, roots = (f"{v}/headline/show-2k.jwt.json", f"{v}/headline/show-2k.json", f"{v}/headline/show-2k.roots.json")
    headline_("A1-headline-2k", "A1", "2k", jwt, show, roots)
    for b in (1, 8, 32, 128):
        headline_(f"S-B-{b}", "S-B", "2k", jwt, show, roots, {"batch": b})
    headline_("X2-headline-1t", "X2", "2k", jwt, show, roots, {"base_cell": "A1-headline-2k"})
    headline_("L5-headline-2k-r1cs", "L5", "2k", jwt, show, roots, extra=["--r1cs-present"])
    rows = [json.loads(l) for l in open(os.path.join(v, "inputs.jsonl"))]
    for r in rows:
        if r["cell"] != "sn_show_n2":
            continue
        base = r["input_path"][:-len(".json")]
        pop = r["population"]["revoked"]
        cells = []
        if r["workload"] == "w1":
            cells += [(f"S-P-r{pop}", "S-P")] + ([("W-w1", "W")] if pop == 1046528 else [])
        elif r["matrix_id"] == "W":
            cells.append((f"W-{r['workload']}", "W"))
        for cell, mid in cells:
            headline_(cell, mid, "2k", jwt, r["input_path"], base + ".roots.json",
                      {"population": r["population"], "workload": r["workload"], "input_sha256_registry": r["input_sha256"]})


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Stage the product cells of the matrices.")
    ap.add_argument("which", nargs="*", choices=["chain", "headline"], help="groups to stage (default: both)")
    ap.add_argument("--only", nargs="+", metavar="CELL", help="stage only these cell ids")
    a = ap.parse_args()
    if a.only and not a.which:
        ap.error("--only needs the group to search: chain or headline")
    only = set(a.only) if a.only else None
    which = a.which or ["chain", "headline"]
    if "chain" in which:
        stage_chain(only)
    if "headline" in which:
        stage_headline(only)
