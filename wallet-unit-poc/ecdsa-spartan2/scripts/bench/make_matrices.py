#!/usr/bin/env python3
"""Write the matrix JSON files in matrices/ for every timed Mac cell of the plan.

Visits: 6 on the A1 chain, 4 on sweeps, 3 single-thread; warm count 5. A cell's `stage` is its path under stage/.
Generic cells name Track B's variants (build/_bench/<name>); product cells name a config and a credential size.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "matrices")
WARM = 5


def product(matrix, config, cell, size, visits, extra_args=(), threads=None, **kw):
    c = {"id": cell, "matrix_id": matrix, "cmd": "run", "stage": f"{config}/{cell}", "config": config,
         "visits": visits, "warm": WARM, "args": ["--size", size, *extra_args]}
    if threads:
        c["threads"] = threads
    c.update(kw)
    return c


def generic(matrix, name, visits, threads=None, **kw):
    c = {"id": f"{matrix}-{name}", "matrix_id": matrix, "cmd": "generic", "stage": f"variant/{matrix}-{name}",
         "config": "variant", "visits": visits, "warm": WARM, "args": []}
    if threads:
        c["threads"] = threads
    c.update(kw)
    return c


def matrices():
    m = {}
    chain = ["v1", "main", "issuer", "revocation", "combined", "headline"]
    m["A1"] = [product("A1", cfg, f"A1-{cfg}-{s}", s, 6) for cfg in chain for s in ("1k", "2k")]
    m["A2"] = ([product("A2", cfg, f"A2-{cfg}-{s}", s, 4) for cfg in ("v1", "combined") for s in ("4k", "8k")]
               + [generic("A2", "jwt_1920", 4, role="prepare")])
    m["S-N"] = ([generic("S-N", f"sn_show_n{n}", 4) for n in (2, 8, 16, 32, 64)]
                + [generic("S-N", f"sn_jwt_n{n}", 4, role="prepare") for n in (8, 16)])
    depths = [(8, 8), (8, 16), (8, 20), (8, 24), (8, 32), (16, 20), (24, 20), (32, 20), (32, 32)]
    # The reference (8,20) point is the S-N reference Show, restaged here with the S-D population.
    m["S-D"] = [generic("S-D", "sn_show_n2" if (di, dr) == (8, 20) else f"sd_d{di}_r{dr}", 4) for di, dr in depths]
    m["S-P"] = [product("S-P", "headline", f"S-P-r{pop}", "2k", 4) for pop in (1024, 32768, 1046528)]
    m["S-MT"] = [generic("S-MT", f"smt_c_m{mm}_t{t}", 4) for mm, t in [(1, 1), (4, 7), (8, 15), (16, 31)]]
    m["S-B"] = [product("S-B", "headline", f"S-B-{b}", "2k", 4, ["--batch", str(b)]) for b in (1, 8, 32, 128)]
    m["W"] = [generic("W", "w2", 4)] + [product("W", "headline", f"W-{w}", "2k", 4) for w in ("w1", "eq_true", "eq_false", "le_true", "le_false", "ge_true", "ge_false")]
    # w2 and w3 need Show(2,4,7,..) and larger (M,T): they run as generic S-MT cells.
    m["X2"] = [product("X2", cfg, f"X2-{cfg}-1t", "2k", 3, threads=1, base_cell=f"A1-{cfg}-2k") for cfg in ("main", "v1", "headline")]
    # X2 shape sweeps are constraint counts only: Track B supplies no witnesses for them.
    m["L5"] = [product("L5", "headline", "L5-headline-2k-r1cs", "2k", 4, r1cs_present=True)]
    m["PM"] = [{"id": f"PM-{cfg}-{s}", "matrix_id": "PM", "cmd": "peakmem", "stage": f"{cfg}/A1-{cfg}-{s}", "config": cfg,
                "visits": 3, "phases": ["prepare", "present", "verify", "online"]}
               for cfg in ("main", "headline") for s in ("2k",)]
    return m


def main():
    os.makedirs(OUT, exist_ok=True)
    for name, cells in matrices().items():
        with open(os.path.join(OUT, f"{name}.json"), "w") as f:
            json.dump({"matrix_id": name, "cells": cells}, f, indent=1)
        print(name, len(cells))


if __name__ == "__main__":
    main()
