#!/usr/bin/env python3
"""Parse Firebase Test Lab logcat output of the OpenAC mobile benchmark.

usage: parse_ftl_bench.py <results_dir | logcat_file> [...] [--out-dir DIR]

Writes bench_iterations.csv, bench_prod.csv, bench_iter.csv and bench_summary.md and prints the summary.
"""
import argparse
import csv
import json
import os
import re
import statistics
import sys

PACKAGE = "com.openac.app"
MARKER_RE = re.compile(r"OPENAC_(DEVICE|SIZES|BENCH|PROD|ITER|ERROR|DONE) (.*)$")
KILL_RES = [
    re.compile(r"(lowmemorykiller|lmkd).*kill.*" + re.escape(PACKAGE), re.I),
    re.compile(r"Process " + re.escape(PACKAGE) + r" \(pid \d+\) has died"),
    re.compile(r"Killing .*" + re.escape(PACKAGE)),
    re.compile(r"Fatal signal|\sF\s+libc\s*:"),
]
LOW_PRIORITY_KILL = re.compile(r"Process .* has died|Killing ")
FINISHED_INST = "due to finished inst"
PID_RE = re.compile(r"^\d\d-\d\d \d\d:\d\d:\d\d\.\d+\s+(\d+)\s+\d+\s")
TAG_RE = re.compile(r"^\d\d-\d\d \d\d:\d\d:\d\d\.\d+\s+\d+\s+\d+\s+[VDIWEF]\s+(.+?)\s*:")
START_PROC_RE = re.compile(r"Start proc (\d+):" + re.escape(PACKAGE))

STEPS = [
    "jwt_setup", "show_setup", "generate_blinds", "prove_jwt", "reblind_jwt",
    "prove_show", "reblind_show", "verify_jwt", "verify_show",
]
CSV_FIELDS = (
    ["device", "soc_model", "mem_total_kb", "config", "iter", "warmup",
     "num_threads", "pin_big_cores", "pool_threads", "pinned_threads",
     "pinned_threads_end"]
    + [f"{s}_ms" for s in STEPS]
    + [f"peak_rss_{s}_kb" for s in STEPS]
    + ["rss_per_step"]
)
PROD_TIMINGS = [
    "prove_jwt_ms", "reblind_jwt_ms", "prove_show_ms", "reblind_show_ms",
    "verify_jwt_wall_ms", "verify_show_wall_ms",
]
PROD_RSS_STEPS = ["prove_jwt", "reblind_jwt", "prove_show", "reblind_show", "verify_jwt", "verify_show"]
PROD_CSV_FIELDS = (
    ["device", "soc_model", "mem_total_kb", "iter"] + PROD_TIMINGS
    + [f"{kind}_rss_{s}_kb" for s in PROD_RSS_STEPS for kind in ("base", "peak")]
    + ["rss_per_step"]
)
ITER_CSV_FIELDS = [
    "device", "soc_model", "mem_total_kb", "step", "iter", "phase", "process_cold", "load_ms",
    "witness_ms", "prove_ms", "total_ms", "base_rss_kb", "peak_rss_kb",
    "mem_available_kb_before", "rss_per_step",
]
# ITER rows of a present run's parts; the iteration itself is the present_total row.
PRESENT_SUBSTEPS = {"show_prove", "prepare_reblind", "show_reblind"}
STAT_STEPS = [
    "prove_jwt_ms", "reblind_jwt_ms", "prove_show_ms", "reblind_show_ms",
    "verify_jwt_ms", "verify_show_ms", "jwt_setup_ms", "show_setup_ms",
]
RSS_STEPS = ["prove_jwt", "prove_show", "jwt_setup"]
KEY_SIZES = [
    ("jwt proving key", "jwt_proving_key_bytes"),
    ("jwt verifying key", "jwt_verifying_key_bytes"),
    ("show proving key", "show_proving_key_bytes"),
    ("show verifying key", "show_verifying_key_bytes"),
    ("jwt witness", "jwt_witness_bytes"),
    ("show witness", "show_witness_bytes"),
]
PROOF_SIZES = [("jwt proof", "jwt_proof_bytes"), ("show proof", "show_proof_bytes")]


def line_pid(line):
    m = PID_RE.match(line)
    return int(m.group(1)) if m else None


def is_flutter_line(line):
    m = TAG_RE.match(line)
    return bool(m) and m.group(1) == "flutter"


def find_kill_reason(line, app_pids=()):
    """The trimmed line if it reports our app dying; foreign processes' fatals are skipped."""
    if FINISHED_INST in line or not any(r.search(line) for r in KILL_RES):
        return None
    if PACKAGE in line or line_pid(line) in app_pids:
        return line.strip()
    return None


def parse_logcat(text):
    res = {"device": None, "sizes": {}, "bench": [], "prod": [], "iters": [], "errors": [], "done": None,
           "malformed": 0, "kill_reason": None}
    app_pids = set()
    kill_lines = []
    for raw in text.splitlines():
        m = MARKER_RE.search(raw)
        if m:
            kind, body = m.groups()
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                data = None
            if not isinstance(data, dict):
                res["malformed"] += 1
                continue
            pid = line_pid(raw)
            if pid is not None and is_flutter_line(raw):
                app_pids.add(pid)
            if kind == "DEVICE":
                res["device"] = data
            elif kind == "SIZES":
                res["sizes"][data.get("config") or data.get("step")] = data
            elif kind == "BENCH":
                res["bench"].append(data)
            elif kind == "PROD":
                for old, new in (("verify_jwt_ms", "verify_jwt_wall_ms"),
                                 ("verify_show_ms", "verify_show_wall_ms")):
                    if old in data and new not in data:
                        data[new] = data.pop(old)
                res["prod"].append(data)
            elif kind == "ITER":
                res["iters"].append(data)
            elif kind == "ERROR":
                res["errors"].append(data)
            else:
                res["done"] = data
        else:
            sp = START_PROC_RE.search(raw)
            if sp:
                app_pids.add(int(sp.group(1)))
            kill_lines.append(raw)
    # Pids are only known once the whole log is read; a fatal can precede the first marker.
    # lmkd and fatal signals beat ActivityManager's "Killing"/"has died", which also
    # follow ordinary shutdowns; ties go to file order.
    found = [(bool(LOW_PRIORITY_KILL.search(r)), i, r) for i, raw in enumerate(kill_lines)
             if (r := find_kill_reason(raw, app_pids))]
    if found:
        res["kill_reason"] = min(found)[2]
    return res


def find_logs(paths):
    """Yields (path, fallback_label) for every logcat file under the inputs."""
    for arg in paths:
        if os.path.isfile(arg):
            stem = os.path.splitext(os.path.basename(arg))[0]
            label = os.path.basename(os.path.dirname(os.path.abspath(arg))) if stem == "logcat" else stem
            yield arg, label
            continue
        for dirpath, _, files in sorted(os.walk(arg)):
            if "logcat" in files:
                rel = os.path.relpath(dirpath, arg)
                top = rel.split(os.sep)[0]
                yield os.path.join(dirpath, "logcat"), (
                    os.path.basename(os.path.abspath(arg)) if top == "." else top)


def load_devices(paths):
    devices = []
    seen = set()
    for path, fallback in find_logs(paths):
        with open(path, errors="replace") as f:
            res = parse_logcat(f.read())
        device = res["device"] or {}
        label = device.get("product_model") or device.get("model") or fallback
        if label in seen:
            label = f"{label} ({fallback})"
        seen.add(label)
        res["label"] = label
        devices.append(res)
    return devices


def status_of(dev):
    if dev["done"] is not None:
        errs = dev["done"].get("errors", 0)
        return "complete" if not errs else f"complete ({errs} errors)"
    counts = {c: sum(1 for b in dev["bench"] if b.get("config") == c) for c in ("A", "B")}
    reason = dev["kill_reason"] or "no OPENAC_DONE"
    if dev["iters"]:
        done = sum(1 for r in dev["iters"] if r.get("step") not in PRESENT_SUBSTEPS)
        return f"FAILED: {reason} ({done} iterations completed)"
    total = len(dev["prod"]) + len(dev["bench"])
    return (f"FAILED: {reason} ({total} iterations completed: "
            f"P={len(dev['prod'])}, A={counts['A']}, B={counts['B']})")


def measured(dev, config):
    return [b for b in dev["bench"] if b.get("config") == config and not b.get("warmup")]


def median_of(rows, key):
    vals = [r[key] for r in rows if r.get(key) is not None]
    return statistics.median(vals) if vals else None


def max_rss_mib(dev, step, config=None):
    vals = [b[f"peak_rss_{step}_kb"] for b in dev["bench"]
            if (config is None or b.get("config") == config)
            and b.get(f"peak_rss_{step}_kb") is not None]
    return max(vals) / 1024 if vals else None


def fmt(v, spec=".1f"):
    return "-" if v is None else format(v, spec)


def prod_increment(rows, step):
    vals = [(r[f"peak_rss_{step}_kb"] - r[f"base_rss_{step}_kb"]) / 1024 for r in rows
            if r.get(f"peak_rss_{step}_kb") is not None and r.get(f"base_rss_{step}_kb") is not None]
    return max(vals) if vals else None


def prod_peak(rows, step):
    peaks = [r[f"peak_rss_{step}_kb"] for r in rows if r.get(f"peak_rss_{step}_kb") is not None]
    return max(peaks) / 1024 if peaks else None


def prod_rss(rows):
    return prod_peak(rows, "prove_jwt"), prod_increment(rows, "prove_jwt")


def prod_section(dev):
    rows = dev["prod"]
    out = [f"### Production path (keys from disk), n={len(rows)}", ""]
    for e in dev["errors"]:
        if e.get("config") == "P" and e.get("iter") == -1:
            out += [f"setup failed: {e.get('error')}", ""]
    if not rows:
        return out
    out += ["| step | median ms | min ms | max ms |", "|---|---|---|---|"]
    for step in PROD_TIMINGS:
        vals = [r[step] for r in rows if r.get(step) is not None]
        if vals:
            label = f"{step} (incl. key/proof load)" if step.endswith("_wall_ms") else step
            out.append(f"| {label} | {statistics.median(vals):.1f} | {min(vals):.1f} | {max(vals):.1f} |")
    note = "" if all(r.get("rss_per_step") for r in rows) else " (process-wide)"
    peak, inc_jwt = prod_rss(rows)
    base = median_of(rows, "base_rss_prove_jwt_kb")
    inc_show = prod_increment(rows, "prove_show")
    peaks = ", ".join(f"{s} {fmt(prod_peak(rows, s))} MiB" for s in ("reblind_jwt", "prove_show", "verify_jwt"))
    incs = ", ".join(f"{s} {fmt(prod_increment(rows, s))} MiB" for s in ("reblind_jwt", "verify_jwt"))
    out += ["",
            f"Max peak RSS prove_jwt: {fmt(peak)} MiB{note}",
            f"Median base RSS prove_jwt: {fmt(base / 1024 if base is not None else None)} MiB{note}",
            f"Prove increment: prove_jwt {fmt(inc_jwt)} MiB, prove_show {fmt(inc_show)} MiB{note}",
            f"Max peak RSS other steps: {peaks}{note}",
            f"Other increments: {incs}{note}",
            ""]
    return out


def iter_groups(dev):
    """(step, cold rows, warm rows) in order of first appearance."""
    steps = {}
    for r in dev["iters"]:
        steps.setdefault(r.get("step"), []).append(r)
    return [(s, [r for r in rows if r.get("phase") == "cold"],
             [r for r in rows if r.get("phase") != "cold"]) for s, rows in steps.items()]


def mib(kb):
    return None if kb is None else kb / 1024


def iter_section(dev):
    out = ["### Article runs (cold = iteration 0 of each step, warm = the rest; process_cold in the CSV marks the process's first)", ""]
    for s, sizes in dev["sizes"].items():
        if s in ("A", "B", "P") or "proof_bytes" not in sizes:
            continue
        parts = [f"{k[:-6].replace('_', ' ')} {v / 1e6:.2f} MB"
                 for k, v in sizes.items() if k.endswith("_bytes") and k != "proof_bytes"
                 and not k.startswith("out_")]
        out.append(f"Sizes ({s}): proof {sizes['proof_bytes'] / 1e3:.1f} KB"
                   + "".join(f", {x}" for x in parts))
    if out[-1] != "":
        out.append("")
    for e in dev["errors"]:
        if e.get("step") is not None:
            out.append(f"Error in {e['step']} iter {e.get('iter')}: {e.get('error')}")
    if out[-1] != "":
        out.append("")
    out += ["| step | phase | n | load ms | prove ms | prove min\u2013max | total ms | base RSS MiB "
            "| peak RSS MiB | MemAvailable before MiB |",
            "|---|---|---|---|---|---|---|---|---|---|"]
    for step, cold, warm in iter_groups(dev):
        for r in cold:
            out.append(
                f"| {step} | cold | 1 | {r.get('load_ms', '-')} | {r.get('prove_ms', '-')} | - "
                f"| {r.get('total_ms', '-')} | {fmt(mib(r.get('base_rss_kb')))} "
                f"| {fmt(mib(r.get('peak_rss_kb')))} | {fmt(mib(r.get('mem_available_kb_before')))} |")
        if warm:
            med = lambda k: median_of(warm, k)
            peaks = [r["peak_rss_kb"] for r in warm if r.get("peak_rss_kb") is not None]
            out.append(
                f"| {step} | warm | {len(warm)} | {fmt(med('load_ms'))} | {fmt(med('prove_ms'))} "
                f"| {span(warm, 'prove_ms')} | {fmt(med('total_ms'))} "
                f"| {fmt(mib(med('base_rss_kb')))} | {fmt(mib(max(peaks)) if peaks else None)} "
                f"| {fmt(mib(med('mem_available_kb_before')))} |")
    out += ["", "Warm rows: median of each column, except peak RSS (max).", ""]
    if any(r.get("rss_per_step") is False for r in dev["iters"]):
        out += ["Peak RSS is process-wide for iterations with rss_per_step=false "
                "(the high-water mark could not be reset).", ""]
    return out


def span(rows, key):
    vals = [r[key] for r in rows if r.get(key) is not None]
    if not vals:
        return "-"
    lo, hi = min(vals), max(vals)
    return str(lo) if lo == hi else f"{lo}\u2013{hi}"


def incomplete_pinning(dev, config):
    """(pinned, pool) of the worst iteration that pinned fewer threads than the pool, else None."""
    short = [(b["pinned_threads"], b["pool_threads"]) for b in dev["bench"]
             if b.get("config") == config and b.get("pin_big_cores")
             and b.get("pinned_threads") is not None and b.get("pool_threads") is not None
             and b["pinned_threads"] < b["pool_threads"]]
    return min(short) if short else None


def pinning_lost(dev, config):
    """(end, pool) of the worst iteration that started fully pinned (or unknown) but ended short."""
    lost = [(b["pinned_threads_end"], b["pool_threads"]) for b in dev["bench"]
            if b.get("config") == config and b.get("pin_big_cores")
            and b.get("pinned_threads_end") is not None and b.get("pool_threads") is not None
            and b["pinned_threads_end"] < b["pool_threads"]
            and not (b.get("pinned_threads") is not None and b["pinned_threads"] < b["pool_threads"])]
    return min(lost) if lost else None


def device_section(dev):
    d = dev["device"] or {}
    out = [f"## {dev['label']}", ""]
    mem = d.get("mem_total_kb")
    freqs = d.get("cpu_max_freq_khz") or []
    out.append(
        f"SoC: {d.get('soc_model', '-')} ({d.get('soc_manufacturer', '-')}) | "
        f"RAM: {fmt(mem / 1024 / 1024 if mem else None)} GiB | "
        f"big cores: {len(d.get('big_cores') or [])}/{len(freqs)}")
    out.append("")
    out.append(f"Status: {status_of(dev)}")
    if dev["malformed"]:
        out.append(f"Malformed marker lines: {dev['malformed']}")
    out.append("")
    for config in ("A", "B"):
        sizes = dev["sizes"].get(config)
        if sizes:
            parts = [f"{n} {sizes[k] / 1e6:.1f} MB" for n, k in KEY_SIZES if k in sizes]
            parts += [f"{n} {sizes[k] / 1e3:.1f} KB" for n, k in PROOF_SIZES if k in sizes]
            out += [f"Sizes (config {config}): " + ", ".join(parts), ""]
    if dev["iters"]:
        out += iter_section(dev)
    if dev["prod"] or any(e.get("config") == "P" for e in dev["errors"]):
        out += prod_section(dev)
    for config in ("A", "B"):
        rows = measured(dev, config)
        if not rows:
            continue
        out += [f"### Config {config} (n={len(rows)})", "",
                f"Threads: pool {span(rows, 'pool_threads')}, pinned {span(rows, 'pinned_threads')} "
                f"(end {span(rows, 'pinned_threads_end')})", ""]
        short = incomplete_pinning(dev, config)
        if short:
            out += [f"WARNING: pinning incomplete (pinned {short[0]} of {short[1]} threads)", ""]
        lost = pinning_lost(dev, config)
        if lost:
            out += [f"WARNING: pinning lost during run (end {lost[0]} of {lost[1]} threads)", ""]
        out += ["| step | median ms | min ms | max ms |", "|---|---|---|---|"]
        for step in STAT_STEPS:
            vals = [r[step] for r in rows if r.get(step) is not None]
            if vals:
                out.append(f"| {step} | {statistics.median(vals):.1f} | {min(vals):.1f} | {max(vals):.1f} |")
        rss = [f"{s} {fmt(max_rss_mib(dev, s, config))} MiB" for s in RSS_STEPS]
        out += ["", "Max peak RSS: " + ", ".join(rss), ""]
    return out


def cross_table(devices):
    out = ["## All devices", "",
           "| device | SoC | RAM GiB | P prove_jwt ms | P prove_jwt peak / increment MiB | A prove_jwt ms | B prove_jwt ms | B/A | A prove_show ms "
           "| max prove_jwt RSS MiB | status |",
           "|---|---|---|---|---|---|---|---|---|---|---|"]
    for dev in devices:
        d = dev["device"] or {}
        mem = d.get("mem_total_kb")
        a = median_of(measured(dev, "A"), "prove_jwt_ms")
        b = median_of(measured(dev, "B"), "prove_jwt_ms")
        show = median_of(measured(dev, "A"), "prove_show_ms")
        p_ms = median_of(dev["prod"], "prove_jwt_ms")
        p_peak, p_inc = prod_rss(dev["prod"])
        p_rss = "-" if p_peak is None else f"{fmt(p_peak)} / {fmt(p_inc)}"
        ratio = b / a if a and b is not None else None
        status = status_of(dev).replace("|", "\\|")
        if len(status) > 80:
            status = status[:77] + "..."
        out.append("| " + " | ".join([
            dev["label"], d.get("soc_model", "-"), fmt(mem / 1024 / 1024 if mem else None),
            fmt(p_ms), p_rss, fmt(a), fmt(b),
            fmt(ratio, ".2f") + (" (pin incomplete)" if incomplete_pinning(dev, "B") or pinning_lost(dev, "B") else ""), fmt(show),
            fmt(max_rss_mib(dev, "prove_jwt")), status]) + " |")
    return out


def summary_md(devices):
    out = ["# OpenAC Android benchmark", ""]
    for dev in devices:
        out += device_section(dev)
    out += cross_table(devices)
    return "\n".join(out) + "\n"


def write_csv(devices, path, fields, key):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore", restval="")
        w.writeheader()
        for dev in devices:
            d = dev["device"] or {}
            for r in dev[key]:
                w.writerow({"device": dev["label"], "soc_model": d.get("soc_model", ""),
                            "mem_total_kb": d.get("mem_total_kb", ""), **r})


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("inputs", nargs="+", help="results dir or logcat file(s)")
    ap.add_argument("--out-dir", help="default: first input (its directory if a file)")
    args = ap.parse_args(argv)

    out_dir = args.out_dir
    if out_dir is None:
        first = args.inputs[0]
        out_dir = first if os.path.isdir(first) else os.path.dirname(os.path.abspath(first))
    os.makedirs(out_dir, exist_ok=True)

    devices = load_devices(args.inputs)
    if not devices:
        print("no logcat files found", file=sys.stderr)
        return 1
    write_csv(devices, os.path.join(out_dir, "bench_iterations.csv"), CSV_FIELDS, "bench")
    write_csv(devices, os.path.join(out_dir, "bench_prod.csv"), PROD_CSV_FIELDS, "prod")
    write_csv(devices, os.path.join(out_dir, "bench_iter.csv"), ITER_CSV_FIELDS, "iters")
    md = summary_md(devices)
    with open(os.path.join(out_dir, "bench_summary.md"), "w") as f:
        f.write(md)
    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
