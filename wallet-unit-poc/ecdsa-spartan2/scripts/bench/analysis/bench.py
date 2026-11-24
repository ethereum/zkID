"""Parser and statistics for the JSONL rows in SCHEMA.md."""
import glob
import json
import os
import re
from collections import defaultdict, namedtuple

Summary = namedtuple("Summary", "median p25 p75 min max n")
Obs = namedtuple("Obs", "v iter proc session src run_id pass_ vk")

DEFAULT_DROP = {"phone": 2, "mac": 0}
PHONE_DIRS = {"iphone17pro": "iphone17pro", "m2q": "s26plus", "s26plus": "s26plus"}
MODELS = {"iPhone18,1": "iphone17pro", "SM-S947U1": "s26plus"}


def quantile(sorted_vals, q):
    """Linear interpolation between order statistics (numpy's default)."""
    pos = (len(sorted_vals) - 1) * q
    lo = int(pos)
    hi = min(lo + 1, len(sorted_vals) - 1)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (pos - lo)


def summarize(vals):
    if not vals:
        return None
    s = sorted(vals)
    return Summary(quantile(s, 0.5), quantile(s, 0.25), quantile(s, 0.75), s[0], s[-1], len(s))


def rel_iqr(s):
    return (s.p75 - s.p25) / s.median


def device_target(name):
    """The target for a DDP device id such as `m2q-36` or `iphone17pro-26-5`."""
    return next((t for k, t in PHONE_DIRS.items() if name.startswith(k)), name)


def target_of(dev, default_dir=None):
    platform = dev.get("platform") or dev.get("os")
    if platform == "macos":
        return "mac"
    model = dev.get("product_model") or dev.get("hw_machine")
    if model in MODELS:
        return MODELS[model]
    if default_dir:
        for prefix, name in PHONE_DIRS.items():
            if default_dir.startswith(prefix):
                return name
    return re.sub(r"\W+", "", model or "unknown").lower()


def population(meta):
    """(issuers, revoked) from the nested `population` dict, with the flat Mac names as a fallback."""
    p = meta.get("population")
    if isinstance(p, dict):
        return p.get("issuers"), p.get("revoked")
    return meta.get("issuers"), meta.get("revoked")


def normalize_meta(dev):
    """Fill d_iss and d_rev from show_params when the producer left them out."""
    m = dict(dev)
    sp = m.get("show_params")
    if sp and "d_iss" not in m and "d_rev" not in m:
        cfg = m.get("config")
        if cfg == "issuer" and len(sp) > 4:
            m["d_iss"], m["d_rev"] = sp[4], 0
        elif cfg == "revocation" and len(sp) > 4:
            m["d_iss"], m["d_rev"] = 0, sp[4]
        elif len(sp) > 5:
            m["d_iss"], m["d_rev"] = sp[4], sp[5]
    return m


class Dataset:
    def __init__(self, drop_warm=None, include_smoke=False):
        self.include_smoke = include_smoke
        self.drop = {**DEFAULT_DROP, **(drop_warm or {})}
        self.series = defaultdict(list)
        self.metas = defaultdict(list)  # every DEVICE row of a cell, in order
        self.problems = []  # (subject, detail): rows the analysis cannot place
        self.errors, self.phonechecks = [], []
        self.cold_skipped = []  # (cell, missing steps): cells with no cold presentation row
        self.excluded_visits = []  # (cell, reason): visits left out of every number
        self.meta, self.sizes, self.flow, self.peaks = {}, defaultdict(dict), defaultdict(dict), defaultdict(float)
        self.shapes, self.registry, self.e2e, self.peakmem = [], [], [], []
        self.crashes, self.rejected, self.excluded = [], [], 0
        self.done_errors = defaultdict(int)
        self._srcs = defaultdict(set)
        self._procs = 0

    @classmethod
    def from_rows(cls, rows, drop_warm=None, source="mem", session=None):
        ds = cls(drop_warm)
        ds.add_rows(rows, source, session)
        return ds

    def add_rows(self, rows, source="mem", session=None, default_config=None, default_dir=None):
        meta, cell, run_id, settled = {}, None, None, False
        proc = -1
        rows = list(rows)
        bad, seg = set(), 0  # (process, iter) pairs an ERROR row rejects
        for raw in rows:
            if raw.get("kind") == "DEVICE":
                seg += 1
            elif raw.get("kind") == "ERROR" and raw.get("iter") is not None:
                bad.add((seg, raw["iter"]))
        seg = 0
        for raw in rows:
            kind = raw.get("kind")
            if (raw.get("smoke") or raw.get("stub")) and not self.include_smoke:
                continue
            row = dict(raw, _src=source)
            if kind == "DEVICE":
                seg += 1
                self._procs += 1
                proc, settled = self._procs, False
                meta = normalize_meta(raw)
                run_id = raw.get("run_id")
                target = target_of(raw, default_dir)
                config = raw.get("config") or default_config
                if not config and target == "mac":
                    config = "main"
                if not config:
                    config = "unknown"
                    self.problems.append((source, "mobile DEVICE row without `config`; it is not defaulted"))
                name = str(raw.get("cell") or "default")
                if raw.get("threads_requested"):
                    name += f"+t{raw['threads_requested']}"
                cell = (target, config, raw.get("matrix_id") or "A1", name)
                reason = None
                if raw.get("gate") == "failed":
                    reason = "idle gate failed"
                elif raw.get("fixture_expect") == "reject":
                    reason = f"fixture {raw.get('fixture')}, expected to be rejected"
                elif raw.get("fixture_expect") is None and raw.get("fixture") is not None:
                    reason = f"fixture {raw['fixture']} has no fixture_expect, so it is not counted as accepted"
                if reason:
                    self.excluded_visits.append((cell, reason))
                    cell = None
                    continue
                self.metas[cell].append(dict(meta, _src=source))
                if cell not in self.meta:
                    self.meta[cell] = dict(meta, _target=target)
                self._srcs[cell].add((source, run_id))
            elif kind == "SIZES" and cell:
                self.sizes[cell].update({k: v for k, v in raw.items() if k != "kind"})
                if "jwt_size" not in self.meta[cell]:
                    for k in raw:
                        m = re.match(r"(\d+k)_", k)
                        if m:
                            self.meta[cell]["jwt_size"] = m.group(1)
                            break
            elif kind == "ITER" and cell:
                if (seg, raw.get("iter")) in bad:
                    self.rejected.append(dict(raw, _cell=cell, _reason="ERROR row for this iteration"))
                    continue
                self._add_iter(raw, cell, proc, session, source, run_id, meta, settled)
                if raw.get("phase") == "settle":
                    settled = True
            elif kind == "DONE" and cell:
                self.done_errors[cell] += raw.get("errors") or 0
            elif kind in ("SHAPE", "CONSTRAINTS"):
                self.shapes.append(self._with_target(row))
            elif kind == "REGISTRY":
                self.registry.append(row)
            elif kind == "E2E":
                self.e2e.append(self._with_target(row))
            elif kind == "PEAKMEM":
                self.peakmem.append(row)
            elif kind == "CRASH":
                self.crashes.append(row)
            elif kind == "ERROR":
                self.errors.append(dict(row, _cell=cell))
            elif kind == "PHONECHECK":
                self.phonechecks.append(row)

    @staticmethod
    def _with_target(row):
        if "platform" in row or "product_model" in row:
            row["_target"] = target_of(row)
        return row

    def _add_iter(self, raw, cell, proc, session, source, run_id, meta, settled):
        phase = raw.get("phase")
        if phase == "settle":
            return
        if settled:
            self.excluded += 1
            return
        if raw.get("ok") is False:
            self.rejected.append(dict(raw, _cell=cell))
            return
        step = raw["step"]
        kind = "mac" if cell[0] == "mac" else "phone"
        if phase == "warm" and raw.get("iter", 0) <= self.drop[kind]:
            return
        self.series[cell + (step, phase)].append(
            Obs(raw["wall_us"] / 1000.0, raw.get("iter", 0), proc, session, source, run_id, meta.get("pass"),
                raw.get("vk_loaded")))
        for k, v in (raw.get("flow") or {}).items():
            if k.endswith("_bytes"):
                self.flow[cell][k] = v
        if raw.get("peak_kb"):
            self.peaks[cell] = max(self.peaks[cell], raw["peak_kb"] * 1024)

    @classmethod
    def load(cls, paths, drop_warm=None, session=None, default_config=None, include_smoke=False):
        ds = cls(drop_warm, include_smoke)
        for p in paths:
            ds.add_rows(read_jsonl(p), source=p, session=session or os.path.basename(os.path.dirname(p)),
                        default_config=default_config)
        return ds

    @classmethod
    def load_root(cls, root, drop_warm=None, include_smoke=False):
        ds = cls(drop_warm, include_smoke)

        def found(*patterns):
            out = []
            for pat in patterns:
                out += glob.glob(os.path.join(root, pat), recursive=True)
            return [p for p in sorted(set(out)) if include_smoke or not is_smoke_path(os.path.relpath(p, root))]

        for p in found("laptop/runs/*/*.jsonl", "laptop/*.jsonl", "laptop/smoke/**/*.jsonl", "variants/*.jsonl", "registry/**/*.jsonl", "e2e/**/*.jsonl",
                       "phonecheck/*.jsonl"):
            ds.add_rows(read_jsonl(p), source=os.path.relpath(p, root), session=os.path.basename(os.path.dirname(p)))
        for p in found("mobile/**/bench*.jsonl"):
            parts = os.path.relpath(p, root).split(os.sep)[1:-1]
            device = next((x for x in parts if any(x.startswith(k) for k in PHONE_DIRS)), None)
            if "openacplus" in parts and parts.index("openacplus") + 1 < len(parts):
                session, config = parts[parts.index("openacplus") + 1], None
            else:
                session = parts[-1] if parts else None
                config = parts[-2] if len(parts) == 3 else None
            ds.add_rows(read_jsonl(p), source=os.path.relpath(p, root), session=session, default_config=config,
                        default_dir=device)
        return ds

    def mixed(self, cell):
        """Provenance keys that differ between the DEVICE rows of one cell, with their values."""
        out = {}
        for key in ("commit", "r1cs_sha256", "keys_sha256", "input_sha256", "wtns_sha256", "binary_sha256", "circuit_commit",
                    "population"):
            vals = {json.dumps(m.get(key), sort_keys=True) for m in self.metas.get(cell, []) if m.get(key) is not None}
            if len(vals) > 1:
                out[key] = sorted(vals)
        return out

    def cells(self):
        return sorted({k[:4] for k in self.series} | set(self.meta), key=str)

    def values(self, cell, step, phase="warm"):
        return [o.v for o in self.series.get(cell + (step, phase), [])]

    def obs(self, cell, step, phase="warm"):
        return self.series.get(cell + (step, phase), [])

    def summary(self, cell, step, phase="warm"):
        """A step name, or a list of steps summed per iteration."""
        if isinstance(step, (list, tuple)):
            return summarize(self.derived(cell, step, phase))
        return summarize(self.values(cell, step, phase))

    def derived(self, cell, steps, phase="warm"):
        """Per-iteration sums of `steps`; an iteration missing any part is skipped."""
        by = [{(o.proc, o.iter): o.v for o in self.obs(cell, s, phase)} for s in steps]
        keys = sorted(set.intersection(*(set(d) for d in by))) if by else []
        return [sum(d[k] for d in by) for k in keys]

    def sources(self, cell):
        return self._srcs.get(cell, set())

    def crash_counts(self):
        out = defaultdict(int)
        for c in self.crashes:
            out[c.get("cell")] += 1
        return dict(out)

    def pick(self, target, config, matrix_id=None, **meta_eq):
        """The cell with the most warm rows among those whose meta matches."""
        best = None
        for c in self.cells():
            if c[0] != target or c[1] != config or (matrix_id and c[2] != matrix_id):
                continue
            if c[3].find("+t") >= 0 and "+t" not in str(meta_eq.get("cell", "")):
                continue
            m = self.meta.get(c, {})
            if any(m.get(k) != v for k, v in meta_eq.items()):
                continue
            n = sum(len(v) for k, v in self.series.items() if k[:4] == c and k[5] == "warm")
            if n and (best is None or n > best[0]):
                best = (n, c)
        return best[1] if best else None

    def shape_rows(self, circuit=None, **eq):
        """Shape rows matching the filters, latest per (circuit, config, params)."""
        out = {}
        for r in self.shapes:
            if circuit and r.get("circuit") != circuit:
                continue
            if any(r.get(k) != v for k, v in eq.items()):
                continue
            key = (r.get("circuit"), r.get("config"), json.dumps(r.get("show_params")), r.get("jwt_size"),
                   r.get("d_iss"), r.get("d_rev"), r.get("matrix_id"))
            out[key] = r
        return list(out.values())


def is_smoke_path(rel):
    return any("smoke" in part for part in rel.split(os.sep))


def read_jsonl(path):
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]
