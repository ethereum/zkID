#!/usr/bin/env python3
"""Write SHAPE rows (C0) for every compiled circuit of one worktree with `openac_bench shape`.

Spartan sizes come from the product proving key when the worktree has one for that circuit.
"""
import argparse
import json
import os
import subprocess
import sys

import stagelib as sl

SHOW_PARAMS = sl.SHOW_PARAMS
JWT_PARAMS = {"jwt": [1920, 1900, 4, 50, 128], "jwt_1k": [1280, 960, 4, 50, 128], "jwt_2k": [2048, 2000, 4, 50, 128],
              "jwt_4k": [4096, 4000, 4, 50, 128], "jwt_8k": [8192, 8000, 4, 50, 128]}


# The source tree each worktree's circuits come from (not the harness commit).
CIRCUIT_COMMIT = {"v1": "1e6b69e", "main": "9557067", "issuer": "38f2d8e", "revocation": "ef842ed", "combined": "f17fffe", "headline": "1deb778"}
DEPTHS = {"v1": (0, 0), "main": (0, 0), "issuer": (8, 0), "revocation": (0, 10), "combined": (8, 10), "headline": (8, 20)}


def jobs(config, circom):
    """(circuit, r1cs path, key size or None) for each compiled circuit."""
    build = os.path.join(circom, "build")
    for name in ["jwt", "jwt_1k", "jwt_2k", "jwt_4k", "jwt_8k", "show", "ecdsa"]:
        r1cs = os.path.join(build, name, f"{name}.r1cs")
        if os.path.exists(r1cs):
            yield name, r1cs, (name.split("_")[1] if name.startswith("jwt_") else "2k" if name == "show" else None)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--worktree", required=True)
    ap.add_argument("--config", required=True, choices=sorted(DEPTHS))
    ap.add_argument("--out", default=None)
    ap.add_argument("--only", nargs="*", help="circuit names to write (default: every compiled one)")
    a = ap.parse_args(argv)
    a.out = a.out or os.path.join(sl.laptop_root(), "shape.jsonl")
    eco = os.path.join(a.worktree, "wallet-unit-poc", "ecdsa-spartan2")
    binary = os.path.join(eco, "target", "release", sl.BIN_NAME)
    env = dict(os.environ)
    libs = __import__("stage").find_libdirs(binary)
    env["DYLD_FALLBACK_LIBRARY_PATH"] = ":".join(libs)
    commit = sl.sh(["git", "-C", a.worktree, "rev-parse", "--short", "HEAD"]).strip()
    d_iss, d_rev = DEPTHS[a.config]
    for name, r1cs, size in jobs(a.config, os.path.join(a.worktree, "wallet-unit-poc", "circom")):
        if a.only and name not in a.only:
            continue
        extra = {"config": "combined" if a.config == "headline" else a.config, "variant_of": "headline" if a.config == "headline" else None,
                 "matrix_id": "C0", "path": "product", "commit": CIRCUIT_COMMIT[a.config], "harness_commit": commit, "spartan2_rev": sl.spartan2_rev(a.worktree),
                 "d_iss": d_iss, "d_rev": d_rev, "show_params": SHOW_PARAMS[a.config] if name == "show" else None,
                 "jwt_params": JWT_PARAMS.get(name), "jwt_size": name.split("_")[1] if name.startswith("jwt_") else "1920" if name == "jwt" else None}
        cmd = [binary, "shape", "--r1cs", r1cs, "--circuit", name, "--out", a.out, "--extra", json.dumps(extra)]
        pk = None if size is None else os.path.join(eco, "keys", f"{size}_{'show' if name == 'show' else 'prepare'}_proving.key")
        if pk and os.path.exists(pk):
            cmd += ["--pk", pk]
        r = subprocess.run(cmd, env=env, capture_output=True, text=True)
        print(a.config, name, "rc", r.returncode, r.stderr[-200:], file=sys.stderr)


if __name__ == "__main__":
    main()
