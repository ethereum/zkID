#!/usr/bin/env python3
"""Peak memory per phase: one `openac_bench` process per phase under `/usr/bin/time -l`, 3 runs each."""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import time

import stagelib as sl

PHASES = ("prepare", "present", "verify", "online")


def time_cmd(binary, d, phase, out, run_id, size="2k", smoke=False):
    return ["/usr/bin/time", "-l", binary, "run", "--dir", d, "--size", size, "--phase", phase, "--warm", "0", "--no-check", "--out", out,
            "--run-id", run_id, *(["--smoke"] if smoke else [])]


def seed_state(d, binary, out, size="2k", smoke=False):
    """One untimed all-in-one run writes the prepared state and a presentation the single-phase runs read."""
    subprocess.run([binary, "run", "--dir", d, "--size", size, "--phase", "all", "--warm", "0", "--save-state", "--save-presentation",
                    "--out", out, "--run-id", "peakmem-seed", *(["--smoke"] if smoke else [])], cwd=d, check=True, capture_output=True)


def provenance(meta, command, threads):
    """Fields a PEAKMEM row carries from the cell's meta.json and the command line."""
    return {"commit": meta.get("commit"), "binary_sha256": meta.get("binary_sha256"), "command": command,
            "d_iss": meta.get("d_iss", 0), "d_rev": meta.get("d_rev", 0), "threads": threads,
            "config": meta.get("config")}


def peak_row(cell, config, phase, run, parsed, prov=None, smoke=False):
    return {"kind": "PEAKMEM", "cell": cell, "phase": phase, "run": run, **parsed, "config": config, **(prov or {}),
            **({"smoke": True} if smoke else {})}


def default_out(smoke):
    """Measurement rows go to peakmem.jsonl, smoke rows under smoke/."""
    return os.path.join(sl.laptop_root(), "smoke", "peakmem.jsonl") if smoke else os.path.join(sl.laptop_root(), "peakmem.jsonl")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", required=True)
    ap.add_argument("--cell", required=True)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--out", help="default: laptop/peakmem.jsonl, or laptop/smoke/peakmem.jsonl with --smoke")
    ap.add_argument("--smoke", action="store_true", help="write under smoke/ and mark every row smoke: true")
    a = ap.parse_args(argv)
    a.out = a.out or default_out(a.smoke)
    d = sl.cell_dir(a.config, a.cell)
    binary = os.path.join(d, sl.BIN_NAME)
    meta = json.load(open(os.path.join(d, "meta.json")))
    size = meta["jwt_size"]
    threads = int(os.environ.get("RAYON_NUM_THREADS") or os.cpu_count())
    procs = os.path.join(os.path.dirname(a.out), "peakmem-procs")
    os.makedirs(procs, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        seed_state(d, binary, os.path.join(tmp, "seed.jsonl"), size, a.smoke)
        for phase in PHASES:
            for run in range(1, a.runs + 1):
                out = os.path.join(procs, f"{a.cell}.{phase}.{run}.jsonl")
                if os.path.exists(out):
                    os.unlink(out)
                cmd = time_cmd(binary, d, phase, out, "peakmem", size, a.smoke)
                r = subprocess.run(cmd, cwd=d, capture_output=True, text=True)
                if r.returncode != 0:
                    sys.exit(f"{phase} run {run} failed: {r.stderr[-300:]}")
                sl.append_jsonl(a.out, peak_row(a.cell, meta["config"], phase, run, sl.parse_time_l(r.stderr), provenance(meta, " ".join(cmd), threads), a.smoke))
                time.sleep(5)


if __name__ == "__main__":
    main()
