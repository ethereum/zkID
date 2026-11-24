#!/usr/bin/env python3
"""Run matrix cells: round-robin over cells, reversed on alternate passes, idle-gated, one CONTROL row per visit.

A visit is one `openac_bench` process. A visit killed by a signal is retried up to 3 times with its rows dropped
and a CRASH row written per attempt.
"""
import argparse
import glob
import json
import os
import signal
import subprocess
import sys
import tempfile
import time

import stagelib as sl

FORBIDDEN_ANY = ("qemu-system", "emulator", "cargo", "rustc")
FORBIDDEN_ABOVE_5 = ("gradle", "flutter", "circom")
MAX_ATTEMPTS = 3


def gate_failures(procs, total_limit=100.0, thermal=0):
    """`procs` is a list of (pcpu, command line). Returns the reasons the machine is not idle."""
    bad = []
    if thermal != 0:
        bad.append("thermal pressure unreadable" if thermal is None else f"thermal pressure {thermal}")
    for pcpu, cmd in procs:
        exe = os.path.basename(cmd.split()[0]) if cmd.split() else ""
        if any(f in exe for f in FORBIDDEN_ANY):
            bad.append(f"{exe} running")
        elif pcpu > 5.0 and any(f in exe for f in FORBIDDEN_ABOVE_5):
            bad.append(f"{exe} at {pcpu}%")
    total = sum(p for p, _ in procs)
    if total >= total_limit:
        bad.append(f"total cpu {total:.0f}%")
    return bad


def ps_snapshot():
    out = sl.sh(["ps", "-axo", "pcpu=,command="])
    procs = []
    for line in out.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            try:
                procs.append((float(parts[0]), parts[1]))
            except ValueError:
                pass
    return procs


def idle_gate(timeout, sleep=time.sleep, snapshot=ps_snapshot, gap=5, thermal=sl.thermal_pressure):
    """True once two checks `gap` seconds apart both pass (nominal thermal pressure included); False on timeout."""
    deadline = time.time() + timeout
    while True:
        if not gate_failures(snapshot(), thermal=thermal()):
            sleep(gap)
            if not gate_failures(snapshot(), thermal=thermal()):
                return True
        if time.time() > deadline:
            return False
        sleep(gap)


def visit_order(cells, passes):
    """[(pass, cell)]: cells in order on even passes, reversed on odd ones; a cell stops after its own visit count."""
    order = []
    for p in range(passes):
        row = [c for c in cells if c["visits"] > p]
        order.extend((p, c) for c in (row if p % 2 == 0 else reversed(row)))
    return order


def bench_path(run_id, smoke):
    """Measurement output goes under runs/, smoke output under smoke/."""
    return os.path.join(sl.laptop_root(), "smoke" if smoke else "runs", run_id, "bench.jsonl")


def smoke_estimates(smoke_dir=None):
    """cell id -> estimated seconds per iteration (warm prepare + present + verify totals) from the newest smoke rows."""
    smoke_dir = smoke_dir or os.path.join(sl.laptop_root(), "smoke")
    est, load = {}, {}
    for path in sorted(glob.glob(os.path.join(smoke_dir, "*", "bench.jsonl")), key=os.path.getmtime):
        cur, steps = None, {}
        for row in sl.read_jsonl(path):
            if row["kind"] == "CONTROL":
                cur = row["cell"]
                steps = {}
                est.pop(cur, None)
            elif row["kind"] == "ITER" and cur:
                if row["phase"] == "warm":
                    steps[row["step"]] = row["wall_us"] / 1e6
                elif row["step"] in ("key_load_prepare", "key_load_show"):
                    load[cur] = load.get(cur, 0) + row["wall_us"] / 1e6
            elif row["kind"] == "DONE" and cur:
                prepare = steps.get("prepare_total", steps.get("prepare_prove", 0))
                est[cur] = prepare + steps.get("present_total", 0) + steps.get("verify_total", 0) + steps.get("batch_reblind", 0)
    return est, load


def estimate_visit_s(cell, est, load, overhead=10):
    if cell["id"] not in est:
        return None
    return load.get(cell["id"], 0) + (1 + cell.get("warm", 5)) * est[cell["id"]] + overhead


def dry_run(cells, gap, gate=10, smoke_dir=None):
    """Lines of `pass cell est_s` in visit order, and the total estimated seconds (unknown cells count 0)."""
    est, load = smoke_estimates(smoke_dir)
    lines, total, unknown = [], 0.0, []
    passes = max(c["visits"] for c in cells)
    for p, cell in visit_order(cells, passes):
        v = estimate_visit_s(cell, est, load)
        if v is None:
            unknown.append(cell["id"])
        total += (v or 0) + gap + gate
        lines.append(f"pass {p} {cell['id']} {'?' if v is None else round(v)}s")
    return lines, total, sorted(set(unknown))


def build_cmd(cell, run_id, out, p, ctl, smoke=False, attempt=1, gate_failed=False):
    d = os.path.join(sl.stage_root(), cell["stage"])
    sub = ["generic", "run"] if cell.get("cmd") == "generic" else ["run"]
    extra = {"visit": p, "pass": p, "attempt": attempt, **({"gate": "failed"} if gate_failed else {}), **{k: ctl.get(k) for k in ("power", "therm", "thermal_pressure")}}
    cmd = [os.path.join(d, sl.BIN_NAME), *sub, "--dir", d, "--out", out, "--warm", str(cell.get("warm", 5)),
           "--run-id", run_id, "--extra", json.dumps(extra), *cell.get("args", []), *(["--smoke"] if smoke else [])]
    env = dict(os.environ)
    if cell.get("threads"):
        env["RAYON_NUM_THREADS"] = str(cell["threads"])
    env.update(cell.get("env", {}))
    return cmd, env, d


def run_visit(cell, run_id, p, ctl, bench_path, runner=subprocess.run, smoke=False, gap=0, gate=None,
              sleep=time.sleep, snapshot=sl.control_snapshot):
    """Returns True when the rows were kept. A retry waits `gap`, re-runs the gate and writes its own CONTROL row."""
    gate_failed = False
    for attempt in range(1, MAX_ATTEMPTS + 1):
        if attempt > 1:
            sleep(gap)
            passed = gate() if gate else None
            control = lambda ok, **more: sl.append_jsonl(bench_path, {**({"smoke": True} if smoke else {}), "kind": "CONTROL", "cell": cell["id"], "pass": p,
                                                                       "attempt": attempt, "idle_gate_pass": ok, **more, **snapshot()})
            if passed is False:
                control(False)
                sleep(gap)
                passed = gate()
            gate_failed = passed is False
            ctl = snapshot()
            control(passed, **({"gate": "failed"} if gate_failed else {}))
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as tmp:
            out = tmp.name
        cmd, env, d = build_cmd(cell, run_id, out, p, ctl, smoke, attempt, gate_failed)
        r = runner(cmd, cwd=d, env=env, capture_output=True, text=True)
        if r.returncode < 0:
            os.unlink(out)
            sl.append_jsonl(bench_path, {**({"smoke": True} if smoke else {}), "kind": "CRASH", "cell": cell["id"], "attempt": attempt, "signal": -r.returncode,
                                         "stderr_tail": r.stderr[-400:], "ts": int(time.time())})
            continue
        with open(out) as f, open(bench_path, "a") as dst:
            dst.write(f.read())
        os.unlink(out)
        if r.returncode != 0:
            print(f"{cell['id']} pass {p}: exit {r.returncode}", file=sys.stderr)
        return True
    return False


def require_smoke_for_overrides(args):
    """--warm, --visits and --no-gate change what a window measures, so they are for smoke runs only."""
    used = [f for f, v in (("--warm", args.warm is not None), ("--visits", args.visits is not None), ("--no-gate", args.no_gate)) if v]
    if used and not args.smoke:
        raise SystemExit(f"{' '.join(used)} only with --smoke")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("matrices", nargs="+", help="matrix JSON files")
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--gap", type=float, default=30, help="seconds between visits")
    ap.add_argument("--gate-timeout", type=float, default=900)
    ap.add_argument("--only", nargs="*", help="cell ids to run")
    ap.add_argument("--warm", type=int, help="override every cell's warm count (smoke runs)")
    ap.add_argument("--visits", type=int, help="override every cell's visit count (smoke runs)")
    ap.add_argument("--dry-run", action="store_true", help="print the visit order and estimated wall time, run nothing")
    ap.add_argument("--smoke", action="store_true", help="write to smoke/<run-id> and mark every row smoke: true")
    ap.add_argument("--no-gate", action="store_true", help="skip the idle gate (smoke runs only)")
    a = ap.parse_args(argv)
    require_smoke_for_overrides(a)
    cells = []
    for m in a.matrices:
        cells.extend(json.load(open(m))["cells"])
    if a.only:
        cells = [c for c in cells if c["id"] in a.only]
    for c in cells:
        c["warm"] = a.warm if a.warm is not None else c.get("warm", 5)
        c["visits"] = a.visits if a.visits is not None else c["visits"]
    cells = [c for c in cells if c.get("cmd") in ("run", "generic")]
    if a.dry_run:
        lines, total, unknown = dry_run(cells, a.gap)
        print("\n".join(lines))
        print(f"estimated wall time: {total / 3600:.2f} h ({len(lines)} visits, gap {a.gap:.0f} s, idle gate about 10 s)")
        if unknown:
            print(f"no smoke estimate for: {' '.join(unknown)}")
        return
    bench = bench_path(a.run_id, a.smoke)
    caffeinate = subprocess.Popen(["caffeinate", "-dimsu"])
    try:
        for p, cell in visit_order(cells, max(c["visits"] for c in cells)):
            ok = None if a.no_gate else idle_gate(a.gate_timeout)
            ctl = sl.control_snapshot()
            sl.append_jsonl(bench, {**({"smoke": True} if a.smoke else {}), "kind": "CONTROL", "cell": cell["id"], "pass": p, "attempt": 1,
                                    "idle_gate_pass": ok, **({"gate": "skipped"} if a.no_gate else {"gate": "failed"} if ok is False else {}), **ctl})
            if ok is False:
                sys.exit("idle gate never passed; stopping")
            run_visit(cell, a.run_id, p, ctl, bench, smoke=a.smoke, gap=a.gap, gate=None if a.no_gate else (lambda: idle_gate(a.gate_timeout)))
            time.sleep(a.gap)
    finally:
        caffeinate.send_signal(signal.SIGTERM)


if __name__ == "__main__":
    main()
