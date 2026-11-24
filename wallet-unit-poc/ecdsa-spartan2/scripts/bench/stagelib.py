"""Shared helpers for the staging, matrix and peak-memory drivers."""
import hashlib
import json
import os
import re
import subprocess
import sys
import time

BIN_NAME = "openac_bench"


def bench_root():
    """OPENACPLUS_BENCH_ROOT: data, stage and runs root. Refused inside a git work tree so ZK artifacts stay out of git."""
    root = os.environ.get("OPENACPLUS_BENCH_ROOT")
    if not root:
        sys.exit("OPENACPLUS_BENCH_ROOT is not set: point it at a directory outside any git checkout")
    root = os.path.abspath(os.path.expanduser(root))
    probe = root
    while not os.path.isdir(probe):
        probe = os.path.dirname(probe)
    inside = subprocess.run(["git", "-C", probe, "rev-parse", "--is-inside-work-tree"], capture_output=True, text=True)
    if inside.stdout.strip() == "true":
        sys.exit(f"OPENACPLUS_BENCH_ROOT={root} is inside a git work tree; use a directory outside any checkout")
    return root


def laptop_root():
    path = os.path.join(bench_root(), "laptop")
    os.makedirs(path, exist_ok=True)
    return path


def stage_root():
    path = os.path.join(laptop_root(), "stage")
    os.makedirs(path, exist_ok=True)
    return path


def worktrees():
    """OPENACPLUS_WORKTREES: a directory holding one worktree per config (v1, main, issuer, revocation, combined, headline)."""
    root = os.environ.get("OPENACPLUS_WORKTREES")
    if not root:
        sys.exit("OPENACPLUS_WORKTREES is not set: point it at the directory holding one worktree per config")
    return os.path.abspath(os.path.expanduser(root))


def worktree(config):
    """Worktree for a stage config; `variant` cells are built from the combined worktree."""
    return os.path.join(worktrees(), "combined" if config == "variant" else config)


def require_worktree(config):
    path = worktree(config)
    if not os.path.isdir(path):
        sys.exit(f"worktree for config '{config}' not found: expected {path} (under OPENACPLUS_WORKTREES)")
    return path


def worktree_binary(config):
    return os.path.join(worktree(config), "wallet-unit-poc", "ecdsa-spartan2", "target", "release", BIN_NAME)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


def hardlink_or_copy(src, dst):
    """Hardlink `src` to `dst`; fall back to a copy across filesystems."""
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    if os.path.exists(dst):
        os.unlink(dst)
    try:
        os.link(src, dst)
    except OSError:
        import shutil
        shutil.copy2(src, dst)


def append_jsonl(path, row):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a") as f:
        f.write(json.dumps(row) + "\n")


def read_jsonl(path):
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


# Show template params per worktree config (v1's Show is Show(128), so null) and JWT params per size.
SHOW_PARAMS = {"v1": None, "main": [2, 2, 8, 64], "issuer": [2, 2, 8, 64, 8], "revocation": [2, 2, 8, 64, 10],
               "combined": [2, 2, 8, 64, 8, 10], "headline": [2, 2, 8, 64, 8, 20]}
JWT_PARAMS = {"jwt": [1920, 1900, 4, 50, 128], "jwt_1k": [1280, 960, 4, 50, 128], "jwt_2k": [2048, 2000, 4, 50, 128],
              "jwt_4k": [4096, 4000, 4, 50, 128], "jwt_8k": [8192, 8000, 4, 50, 128]}


def product_params(stage_config, size):
    """(show_params, jwt_params) for a product cell staged under `stage_config` with credential size `size`."""
    return SHOW_PARAMS[stage_config], JWT_PARAMS[f"jwt_{size}"]


def cell_dir(config, cell):
    return os.path.join(stage_root(), config, cell)


def parse_time_l(stderr):
    """Max RSS, peak footprint (bytes) and wall seconds from `/usr/bin/time -l` output."""
    def grab(pattern, cast):
        m = re.search(pattern, stderr, re.M)
        return cast(m.group(1)) if m else None
    return {
        "max_rss_bytes": grab(r"^\s*(\d+)\s+maximum resident set size", int),
        "peak_footprint_bytes": grab(r"^\s*(\d+)\s+peak memory footprint", int),
        "wall_s": grab(r"^\s*([\d.]+)\s+real", float),
    }


def parse_pmset_therm(text):
    m = re.search(r"CPU_Speed_Limit\s*=\s*(\d+)", text)
    return int(m.group(1)) if m else 100


def parse_pmset_power(text):
    return "ac" if "AC Power" in text else "battery"


def parse_low_power(text):
    m = re.search(r"lowpowermode\s+(\d)", text)
    return bool(m and m.group(1) == "1")


def sh(cmd):
    return subprocess.run(cmd, capture_output=True, text=True).stdout


def parse_thermal_pressure(text):
    """Level from `notifyutil -g com.apple.system.thermalpressurelevel` output; None when unreadable."""
    m = re.search(r"thermalpressurelevel\s+(\d+)", text)
    return int(m.group(1)) if m else None


def thermal_pressure():
    return parse_thermal_pressure(sh(["notifyutil", "-g", "com.apple.system.thermalpressurelevel"]))


def control_snapshot():
    return {
        "power": parse_pmset_power(sh(["pmset", "-g", "batt"])),
        "therm": parse_pmset_therm(sh(["pmset", "-g", "therm"])),
        "low_power_mode": parse_low_power(sh(["pmset", "-g"])),
        "thermal_pressure": thermal_pressure(),
        "load_avg_1m": os.getloadavg()[0],
        "ts": int(time.time()),
    }


def path_lens(show_input):
    """(iss_path_len, rev_path_len) from a Show input JSON; 0 for a tree the circuit does not have."""
    with open(show_input) as f:
        v = json.load(f)
    one = lambda x: int(x[0] if isinstance(x, list) else x)
    return one(v.get("issuerTreeDepth", 0)), one(v.get("revocationDepth", 0))


def update_meta(cell, updates):
    """Merge `updates` into a staged cell's meta.json without touching anything else."""
    p = os.path.join(cell, "meta.json")
    with open(p) as f:
        meta = json.load(f)
    meta.update(updates)
    with open(p, "w") as f:
        json.dump(meta, f, indent=1)
    return meta


def patch_path_lens(cell, show_input):
    """Writes iss_path_len and rev_path_len into a staged cell's meta.json without touching anything else."""
    p = os.path.join(cell, "meta.json")
    with open(p) as f:
        meta = json.load(f)
    meta["iss_path_len"], meta["rev_path_len"] = path_lens(show_input) if show_input else (0, 0)
    with open(p, "w") as f:
        json.dump(meta, f, indent=1)
    return meta["iss_path_len"], meta["rev_path_len"]
