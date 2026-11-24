#!/usr/bin/env python3
"""Stage the generic-path cells from inputs.jsonl: layout from the .sym, `generic setup`, then stage.py generic.

Show cells time Show alone; sn_jwt_* and jwt_1920 are Prepare-only (`linked: false`).
"""
import json
import os
import subprocess
import sys

import layout
import stage
import stagelib as sl

CIRCUIT_COMMIT_FALLBACK = "fe571a5"


def cells_for(row):
    """[(stage cell id, role, n_claims)] for an INPUT row; empty when the row is not a generic cell."""
    name, mid, wl = row["cell"], row["matrix_id"], row["workload"]
    if name.startswith("sn_jwt_n"):
        return [(f"S-N-{name}", "prepare", int(name.rsplit("n", 1)[1]))]
    if name == "jwt_1920":
        return [("A2-jwt_1920", "prepare", 2)]
    if name == "sn_show_n2" and mid == "A1":
        return [("S-N-sn_show_n2", "show", 2)]
    if name == "sn_show_n2" and mid == "S-D":
        return [("S-D-sn_show_n2", "show", 2)]
    if name.startswith("sn_show_n") and name != "sn_show_n2":
        return [(f"S-N-{name}", "show", int(name.rsplit("n", 1)[1]))]
    if name.startswith("sd_"):
        return [(f"S-D-{name}", "show", 2)]
    if name.startswith("smt_c_") and wl == "w3":
        return [(f"S-MT-{name}", "show", 2)]
    if name == "smt_c_m4_t7" and wl == "w2":
        return [("W-w2", "show", 2)]
    return []


def parse_only(argv):
    """Cell ids from `--only a b` plus bare positionals; flags such as --patch-meta are skipped."""
    only, collecting = set(), False
    for a in argv:
        if a.startswith("--"):
            collecting = a == "--only"
        else:
            only.add(a)
    return only


def main():
    only = parse_only(sys.argv[1:])
    for line in open(os.path.join(sl.bench_root(), "variants", "inputs.jsonl")):
        row = json.loads(line)
        for cell, role, n in cells_for(row):
            if only and cell not in only:
                continue
            stage_cell(row, cell, role, n)


def build_meta(row, role, setup_out):
    """meta.json fields for a generic cell. Prepare-only cells carry no Show parameters, population or workload."""
    meta = {"role": role, "r1cs_sha256": sl.sha256_file(row["r1cs_path"]), "spartan2_rev": sl.spartan2_rev(sl.worktree("combined")),
            "input_json_sha256": row.get("jwt_input_sha256") or row.get("input_sha256"),
            "wtns_sha256": row.get("jwt_wtns_sha256") or row.get("wtns_sha256"),
            "circuit_commit": row.get("circuit_commit") or row.get("commit") or CIRCUIT_COMMIT_FALLBACK,
            "setup": json.loads(open(setup_out).read()) if os.path.exists(setup_out) else None}
    if role == "prepare":
        meta.update({"show_params": None, "population": None, "workload": None, "linked": False, "d_iss": 0, "d_rev": 0,
                     "roots_source": "none", **({"jwt_size": "1920"} if row.get("cell") == "jwt_1920" else {})})
        return meta
    params = row.get("show_params") or [0] * 6
    meta.update({"show_params": row.get("show_params"), "population": row.get("population"), "workload": row["workload"],
                 "d_iss": params[4], "d_rev": params[5],
                 "roots_source": "registry" if row.get("roots_match_circuit") else "circuit"})
    return meta


def stage_cell(row, cell, role, n):
    binary = sl.worktree_binary("combined")
    kd = os.path.join(sl.laptop_root(), "generic-keys", cell)
    os.makedirs(kd, exist_ok=True)
    lay = os.path.join(kd, "layout.json")
    derived = layout.derive(role, row["sym_path"], row["r1cs_path"], n)
    have = os.path.exists(os.path.join(kd, "generic_proving.key")) and os.path.exists(lay) and json.load(open(lay)) == derived
    setup_out = os.path.join(kd, "setup.json")
    if not have:
        with open(lay, "w") as f:
            json.dump(derived, f)
        env = dict(os.environ, DYLD_FALLBACK_LIBRARY_PATH=":".join(stage.find_libdirs(binary)))
        r = subprocess.run([binary, "generic", "setup", "--r1cs", row["r1cs_path"], "--layout", lay, "--keys", kd], env=env, capture_output=True, text=True)
        if r.returncode:
            sys.exit(f"{cell}: setup failed: {r.stderr[-300:]}")
        open(setup_out, "w").write(r.stdout.strip().splitlines()[-1])
    if "--patch-meta" in sys.argv[1:]:
        keep = ("circuit_commit", "roots_source", "show_params", "population", "workload", "linked", "d_iss", "d_rev", "jwt_size", "input_json_sha256", "wtns_sha256")
        sl.update_meta(sl.cell_dir("variant", cell), {k: v for k, v in build_meta(row, role, setup_out).items() if k in keep})
        sl.patch_path_lens(sl.cell_dir("variant", cell), None if role == "prepare" else row["input_path"])
        return
    stage.main(["generic", "--binary", binary, "--cell", cell, "--keys", kd, "--wtns", row.get("jwt_wtns_path") or row["wtns_path"], "--layout", lay,
                "--matrix-id", next(p for p in ("S-N", "S-D", "S-MT", "W", "A2") if cell.startswith(p + "-")),
                "--meta", json.dumps(build_meta(row, role, setup_out))] + ([] if role == "prepare" else ["--show-input", row["input_path"]]))


if __name__ == "__main__":
    main()
