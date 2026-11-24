"""Acceptance checks from the plan's "Final numbers are done when" list."""
import glob
import json
import os
from collections import defaultdict, namedtuple

from bench import device_target, population, rel_iqr, summarize

Check = namedtuple("Check", "name subject status value limit detail")

FAST_MS, FAST_IQR_MS = 40, 2.0
PHONE_STEPS = ("prepare_prove", "present_total")


def _c(name, subject, ok, value, limit, detail=""):
    return Check(name, subject, "pass" if ok else "fail", value, limit, detail)


def _info(name, subject, value, detail=""):
    """A reported result, not a gate."""
    return Check(name, subject, "info", value, None, detail)


def show_step(ds, cell):
    """Population and depth comparisons use the prove without witness generation when the cell has it."""
    return "show_prove_only" if ds.series.get(cell + ("show_prove_only", "warm")) else "show_prove"


def _skip(name, why):
    return Check(name, "all", "skip", None, None, why)


def fmt_cell(cell):
    return "/".join(cell)


def _phone_cells(ds):
    return [c for c in ds.cells() if c[0] != "mac"]


def iqr_ok(s, limit):
    """Relative IQR within `limit`, or for steps under 40 ms an absolute IQR of at most 2 ms."""
    return rel_iqr(s) <= limit or (s.median < FAST_MS and s.p75 - s.p25 <= FAST_IQR_MS)


def check_iqr(ds, limit=0.05):
    out = []
    for key in sorted(ds.series, key=str):
        if key[0] != "mac" or key[5] != "warm":
            continue
        s = summarize(ds.values(key[:4], key[4]))
        if s.n < 2 or s.median <= 0:
            continue
        out.append(_c("iqr", f"{fmt_cell(key[:4])}/{key[4]}", iqr_ok(s, limit), rel_iqr(s), limit,
                      f"n={s.n}, absolute IQR {s.p75 - s.p25:.2f} ms"))
    return out


def check_registry_iqr(ds, limit=0.05):
    groups = defaultdict(list)
    for r in ds.registry:
        if r.get("wall_us") is not None and r.get("phase", "warm") == "warm" and r.get("op") != "bandwidth":
            groups[(r["registry"], r["op"], r.get("method") or "", r.get("k") or 0, r["population"])].append(r["wall_us"] / 1000)
    out = []
    for key, vals in sorted(groups.items(), key=str):
        s = summarize(vals)
        if s.n >= 2 and s.median > 0:
            out.append(_c("registry_iqr", "/".join(map(str, key)), iqr_ok(s, limit), rel_iqr(s), limit,
                          f"n={s.n}, absolute IQR {s.p75 - s.p25:.3f} ms"))
    return out or [_skip("registry_iqr", "no registry operation has two warm rows")]


def _by_pass(ds, cell, step):
    groups = defaultdict(list)
    for o in ds.obs(cell, step):
        groups[o.pass_].append(o.v)
    return groups


def check_mac_drift(ds, limit=0.03):
    out = []
    for key in sorted(ds.series, key=str):
        if key[0] != "mac" or key[5] != "warm":
            continue
        groups = _by_pass(ds, key[:4], key[4])
        if None in groups and len(groups) > 1:
            out.append(Check("mac_drift", f"{fmt_cell(key[:4])}/{key[4]}", "fail", None, limit,
                             f"{len(groups[None])} rows without `pass` next to rows with one"))
            continue
        if len(groups) < 2:
            continue
        s = summarize([v for sub in groups.values() for v in sub])
        if s.median <= 0:
            continue
        first, last = groups[min(groups)], groups[max(groups)]
        d = abs(summarize(last).median - summarize(first).median) / summarize(first).median
        out.append(_info("mac_drift", f"{fmt_cell(key[:4])}/{key[4]}", d,
                         f"first against last pass ({min(groups)} vs {max(groups)}); reported, limit {limit:.0%} is not a gate"))
    return out or [_skip("mac_drift", "no cell has two passes")]


def check_phone_drift(ds, limit=0.05, k=6):
    out = []
    for cell in _phone_cells(ds):
        for step in PHONE_STEPS:
            procs = defaultdict(list)
            for o in ds.obs(cell, step):
                procs[(o.session, o.proc)].append(o)
            for (session, _), obs in sorted(procs.items(), key=str):
                vals = [o.v for o in sorted(obs, key=lambda o: o.iter)]
                # Sessions of 12 warm iterations keep 10 after the phone drop, so they compare 5 against 5.
                n = min(k, len(vals) // 2)
                if n < 5:
                    continue
                a, b = summarize(vals[:n]).median, summarize(vals[-n:]).median
                d = abs(b - a) / a
                out.append(_c("phone_drift", f"{fmt_cell(cell)}/{step}/{session}", d <= limit, d, limit,
                              f"first {n} {a:.1f} ms, last {n} {b:.1f} ms"))
    return out or [_skip("phone_drift", "no phone process has 10 warm rows")]


def check_session_spread(ds, limit=0.10):
    out = []
    for cell in _phone_cells(ds):
        for step in PHONE_STEPS:
            per = defaultdict(list)
            for o in ds.obs(cell, step):
                per[o.session].append(o.v)
            if len(per) < 2:
                continue
            meds = [summarize(v).median for v in per.values()]
            mid = summarize(meds).median
            sp = (max(meds) - min(meds)) / mid
            out.append(_c("session_spread", f"{fmt_cell(cell)}/{step}", sp <= limit, sp, limit,
                          f"{len(per)} sessions"))
    return out or [_skip("session_spread", "no phone cell has two sessions")]


def check_sp_span(ds, limit=0.03):
    """The population span of Show prove time, reported as a result rather than gated."""
    out = []
    by_target = defaultdict(list)
    for c in ds.cells():
        if c[2] == "S-P":
            step = show_step(ds, c)
            m = ds.summary(c, step)
            if m:
                by_target[(c[0], c[1], step)].append(m.median)
    for (target, config, step), meds in sorted(by_target.items()):
        if len(meds) < 2:
            continue
        span = (max(meds) - min(meds)) / min(meds)
        out.append(_info("sp_span", f"{target}/{config}/{step}", span,
                         f"{len(meds)} populations; reported, {limit:.0%} is not a gate"))
    return out or [_skip("sp_span", "fewer than two S-P cells")]


BRIDGE_STEPS = ("prepare_prove", "show_prove", "present_total", "verify")
MATCH_KEYS = ("jwt_size", "d_iss", "d_rev")


def check_bridge(ds, limit=0.10):
    out = []
    for br in ds.cells():
        if br[2] != "BR":
            continue
        m = ds.meta[br]
        ref = ds.pick(br[0], br[1], "A1", **{k: m.get(k) for k in MATCH_KEYS})
        if not ref:
            out.append(Check("bridge", fmt_cell(br), "fail", None, limit, "no matching openac_bench A1 cell"))
            continue
        for step in BRIDGE_STEPS:
            a, b = ds.summary(br, step), ds.summary(ref, step)
            if not a or not b:
                continue
            d = abs(a.median - b.median) / b.median
            out.append(_c("bridge", f"{fmt_cell(br)}/{step}", d <= limit, d, limit,
                          f"vs {fmt_cell(ref)}"))
    return out or [_skip("bridge", "no BR cells")]


OVERLAPPED = {"vk_load", "vk_digest", "verify_total", "prepare_total", "show_total"}


def e2e_total(row):
    """The row's total, else the sum of non-overlapping stages: show_prove sits inside present_total, VK loads are reported apart."""
    if row.get("total_us") is not None:
        return row["total_us"]
    stages = row.get("stages", [])
    names = {s["name"] for s in stages}
    keep = [s for s in stages if s["name"] not in OVERLAPPED and not (s["name"] == "show_prove" and "present_total" in names)]
    return sum(s["wall_us"] for s in keep) or None


def e2e_key(r):
    """Rows are only comparable within one target, config, workload, k, population and batch."""
    return (r.get("_target"), r.get("config"), r.get("workload"), r.get("k") or 0, population(r)[1], r.get("batch"))


def check_composed_e2e(ds, limit=0.10):
    groups = defaultdict(lambda: defaultdict(list))
    for r in ds.e2e:
        t = e2e_total(r)
        if t:
            groups[e2e_key(r)][bool(r.get("composed"))].append(t)
    out = []
    for key, d in sorted(groups.items(), key=str):
        if True in d and False in d:
            c, o = summarize(d[True]).median, summarize(d[False]).median
            out.append(_c("composed_e2e", "/".join(map(str, key)), abs(c - o) / o <= limit, abs(c - o) / o, limit,
                          f"median composed {c / 1e3:.0f} ms, orchestrated {o / 1e3:.0f} ms"))
    return out or [_skip("composed_e2e", "no workload has both a composed and an orchestrated run")]


def loaded_counts(row):
    """(header, loaded) counts: `constraints` against `loaded_constraints`; the older header_* names are a fallback."""
    if row.get("loaded_constraints") is not None:
        return (row.get("constraints"), row.get("wires")), (row["loaded_constraints"], row.get("loaded_wires"))
    if row.get("header_constraints") is not None:
        return (row.get("constraints"), row.get("wires")), (row["header_constraints"], row.get("header_wires"))
    return None, None


def check_r1cs_header(ds):
    out = []
    for r in ds.shapes:
        if r.get("kind") != "SHAPE":
            continue
        head, loaded = loaded_counts(r)
        if head is None:
            continue
        ok = head[0] == loaded[0] and (loaded[1] is None or head[1] == loaded[1])
        out.append(_c("r1cs_header", f"{r.get('config')}/{r.get('circuit')}", ok, loaded[0] - head[0], 0,
                      f"shape {head[0]}/{head[1]}, loaded {loaded[0]}/{loaded[1]}"))
    return out or [_skip("r1cs_header", "no SHAPE row carries loaded_constraints")]


def check_crashes(ds):
    crashes, rejected, errors = ds.crash_counts(), defaultdict(int), defaultdict(int)
    for r in ds.rejected:
        rejected[r["_cell"][3]] += 1
    for cell, n in ds.done_errors.items():
        errors[cell[3]] += n
    names = sorted(set(crashes) | set(rejected) | set(errors) | {c[3] for c in ds.cells()}, key=str)
    out = []
    for n in names:
        cr, rj, er = crashes.get(n, 0), rejected.get(n, 0), errors.get(n, 0)
        detail = f"{cr} crash, {rj} not-ok, {er} errors in DONE"
        if rj or er:
            out.append(_c("crashes", str(n), False, cr + rj + er, 0, detail))
        elif cr:
            out.append(_info("crashes", str(n), cr, detail + "; retried crashes are counted, the visit gate decides"))
        else:
            out.append(_c("crashes", str(n), True, 0, 0, detail))
    return out


def check_excluded_visits(ds):
    n = defaultdict(int)
    for cell, reason in ds.excluded_visits:
        n[(cell[3], reason)] += 1
    return [_info("excluded_visits", cell, k, f"{k} visit(s) left out: {reason}") for (cell, reason), k in sorted(n.items())]


def check_provenance_mix(ds):
    out = []
    for cell in ds.cells():
        mixed = ds.mixed(cell)
        if mixed:
            out.append(Check("provenance_mix", fmt_cell(cell), "fail", None, None,
                             "rows of one cell differ in " + ", ".join(f"{k} ({len(v)} values)" for k, v in mixed.items())))
    if out:
        return out
    return [_c("provenance_mix", "all", True, 0, 0, "no cell mixes commit, r1cs_sha256 or keys_sha256")] if ds.cells() else \
        [_skip("provenance_mix", "no cells")]


HEAD_PARAMS = [2, 2, 8, 64, 8, 20]


def check_product_generic(ds, limit=0.10):
    """Product show_prove_only against generic show_prove for the headline Show, at the same registry population."""
    prod = ds.pick("mac", "combined", "A1", d_iss=8, d_rev=20, jwt_size="2k")
    pop = population(ds.meta[prod])[1] if prod else None
    gens = [c for c in ds.cells() if c[0] == "mac" and ds.meta[c].get("path") == "generic"
            and ds.meta[c].get("show_params") == HEAD_PARAMS and population(ds.meta[c])[1] == pop]
    gen = max(gens, key=lambda c: (c[2] == "S-N", len(ds.values(c, "show_prove"))), default=None)
    a = ds.summary(prod, "show_prove_only") if prod else None
    b = ds.summary(gen, "show_prove") if gen else None
    if not a or not b:
        return [_skip("product_generic", "needs a product cell with show_prove_only and a generic (8,20) Show cell "
                                         f"at the same population ({pop})")]
    d = abs(a.median - b.median) / a.median
    return [_c("product_generic", f"{fmt_cell(prod)} vs {fmt_cell(gen)}", d <= limit, d, limit,
               f"product show_prove_only {a.median:.1f} ms, generic show_prove {b.median:.1f} ms, population {pop}")]


def check_cold_skipped(ds):
    return [_info("cold_skipped", fmt_cell(cell), None,
                  "no cold presentation row; missing: " + (", ".join(missing) or "no visit has every stage"))
            for cell, missing in ds.cold_skipped]


def check_data(ds):
    return [Check("data", str(subject), "fail", None, None, detail) for subject, detail in ds.problems]


def _cells(directory):
    for path in sorted(glob.glob(os.path.join(directory, "*.json"))):
        with open(path) as f:
            yield from json.load(f).get("cells", [])


def load_matrices(directory):
    """{cell id: required visits} for the timed cells; peakmem cells are counted by their PEAKMEM runs instead."""
    return {c["id"]: c["visits"] for c in _cells(directory) if c.get("visits") and c.get("cmd") != "peakmem"}


def load_pm(directory):
    """[(cell the PEAKMEM rows name, phase, required runs)] from the peakmem matrix cells."""
    return [(c["stage"].split("/")[-1], phase, c["visits"]) for c in _cells(directory) if c.get("cmd") == "peakmem"
            for phase in c.get("phases", [])]


def gate_peakmem(ds, pm):
    if not pm:
        return [Check("peakmem", "all", "fail", None, None, "no peakmem matrix cells found")]
    out = []
    for cell, phase, need in pm:
        have = len({r.get("run") for r in ds.peakmem if r.get("cell") == cell and r.get("phase") == phase})
        out.append(_c("peakmem", f"{cell}/{phase}", have >= need, have, need, f"{have} of {need} runs"))
    return out


def gate_gc(ds):
    """Registry and orchestrated E2E rows must come from a process with gc exposed."""
    rows = [r for r in ds.registry if r.get("op") != "bandwidth"] + [r for r in ds.e2e if not r.get("_derived")]
    if not rows:
        return [Check("gc", "all", "fail", None, None, "no REGISTRY or E2E rows")]
    bad = [r for r in rows if r.get("gc_exposed") is not True]
    return [_c("gc", "all", not bad, len(bad), 0, f"{len(bad)} of {len(rows)} rows lack gc_exposed: true")]


def gate_visits(ds, expected):
    if not expected:
        return [Check("visits", "all", "fail", None, None, "no matrix files found")]
    have = defaultdict(int)
    for c in ds.cells():
        if c[0] == "mac":
            have[c[3].split("+t")[0]] += len(ds.metas.get(c, []))
    return [_c("visits", cell, have.get(cell, 0) >= need, have.get(cell, 0), need, f"{have.get(cell, 0)} of {need} visits")
            for cell, need in sorted(expected.items())]


def gate_provenance(rows):
    if not rows:
        return [Check("provenance", "all", "fail", 0, 0, "no numbers were recorded")]
    dirty = [r["table_cell"] for r in rows if "-dirty" in f"{r.get('commit')};{r.get('bench_sha')}"]
    if dirty:
        return [Check("provenance", "all", "fail", len(dirty), 0,
                      f"{len(dirty)} numbers come from a dirty tree (commit ends in -dirty), e.g. " + ", ".join(dirty[:5]))]
    bad = [r["table_cell"] for r in rows if "unrecorded" in (r.get("command"), r.get("spartan2_rev"))
           or (r.get("commit") in (None, "", "unrecorded") and r.get("bench_sha") in (None, "", "unrecorded"))]
    if bad:
        return [Check("provenance", "all", "fail", len(bad), 0,
                      f"{len(bad)} of {len(rows)} numbers lack a commit, command or spartan2_rev, e.g. " + ", ".join(bad[:5]))]
    return [_c("provenance", "all", True, 0, 0, f"{len(rows)} numbers, all with commit, command and spartan2_rev")]


def load_expected_sessions(path):
    try:
        with open(path) as f:
            return json.load(f)
    except OSError:
        return {}


def gate_sessions(ds, expected):
    """Every device/config pair needs its expected number of measured, non-smoke sessions."""
    if not expected:
        return [Check("sessions", "all", "fail", None, None, "no expected_sessions.json")]
    have = defaultdict(set)
    for key, obs in ds.series.items():
        if key[0] != "mac":
            have[(key[0], key[1])] |= {o.session for o in obs}
    return [_c("sessions", f"{device_target(dev)}/{config}", len(have[(device_target(dev), config)]) >= need,
               len(have[(device_target(dev), config)]), need, f"{len(have[(device_target(dev), config)])} of {need} sessions")
            for dev, configs in sorted(expected.items()) for config, need in sorted(configs.items())]


def gate_phonecheck(ds):
    sessions = set()
    for key, obs in ds.series.items():
        if key[0] != "mac":
            sessions |= {(key[0], key[1], o.session) for o in obs}
    if not sessions:
        return [Check("phonecheck", "all", "fail", None, None, "no phone sessions")]
    out = []
    for target, config, session in sorted(sessions, key=str):
        hits = [p for p in ds.phonechecks if p.get("device") == target and p.get("config") == config
                and p.get("session") == session]
        ok = bool(hits) and all(p.get("proofs_valid") and p.get("linked") and p.get("roots_match_registry") for p in hits)
        out.append(_c("phonecheck", f"{target}/{config}/{session}", ok, None, None,
                      "proofs valid, linked, roots match the registry" if ok else
                      ("no PHONECHECK row" if not hits else "a PHONECHECK field is false")))
    return out


ALL = (check_excluded_visits, check_data, check_provenance_mix, check_registry_iqr, check_product_generic, check_iqr, check_mac_drift, check_phone_drift, check_session_spread, check_sp_span, check_bridge,
       check_composed_e2e, check_cold_skipped, check_r1cs_header, check_crashes)


# Reported results, and a comparison that only exists where both runs do: absent data is not a failure.
INFO_WHEN_ABSENT = {"mac_drift", "sp_span", "composed_e2e"}


def run_all(ds, final=False):
    """A check that raises becomes a FAIL line instead of stopping the run. With `final`, a skip is a FAIL."""
    out = []
    for f in ALL:
        try:
            out += f(ds)
        except Exception as e:  # noqa: BLE001
            out.append(Check(f.__name__.removeprefix("check_"), "all", "fail", None, None,
                             f"check error: {type(e).__name__}: {e}"))
    if final:
        out = [Check(c.name, c.subject, "fail", c.value, c.limit, f"no data (--final): {c.detail}")
               if c.status == "skip" and c.name not in INFO_WHEN_ABSENT else c for c in out]
    return out


def render_md(checks, ds, skipped=(), notes=()):
    lines = ["# Checks", "", "| check | subject | status | value | limit | detail |", "|---|---|---|---|---|---|"]
    for c in checks:
        v = "" if c.value is None else (f"{c.value:.4f}" if isinstance(c.value, float) else str(c.value))
        lim = "" if c.limit is None else str(c.limit)
        lines.append(f"| {c.name} | {c.subject} | {c.status} | {v} | {lim} | {c.detail} |")
    n = defaultdict(int)
    for c in checks:
        n[c.status] += 1
    lines += ["", f"Totals: {n['pass']} pass, {n['fail']} fail, {n['skip']} skip, {n['info']} info (reported, not gated).",
              f"Rejected rows: {len(ds.rejected)}. Crash rows: {len(ds.crashes)}. "
              f"Rows after a settle pass, not used: {ds.excluded}.", ""]
    lines += [f"SKIP {name}: no rows" for name in skipped] + list(dict.fromkeys(notes))
    return "\n".join(lines) + ("\n" if skipped or notes else "")
