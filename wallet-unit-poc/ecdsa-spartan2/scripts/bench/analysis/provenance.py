"""One provenance row for every number that lands in a table or figure."""
import csv

COLUMNS = ("table_cell", "value", "unit", "device", "bench_sha", "base_sha", "commit", "spartan2_rev", "command",
           "source_files", "run_ids", "measures")


def _join(vals):
    return ";".join(sorted({str(v) for v in vals if v not in (None, "")})) or "unrecorded"


class Prov:
    def __init__(self, ds):
        self.ds = ds
        self.rows = []

    def add(self, tag, value, device, measures, unit="", cells=(), rows=()):
        metas = [m for c in cells for m in (self.ds.metas.get(c) or [self.ds.meta.get(c, {})])] + list(rows)
        srcs = [s for c in cells for s in self.ds.sources(c)] + [(r.get("_src"), r.get("run_id")) for r in rows]
        self.rows.append({
            "table_cell": tag, "value": value, "unit": unit, "device": device,
            "bench_sha": _join(m.get("bench_sha") for m in metas),
            "base_sha": _join(m.get("base_sha") for m in metas),
            "commit": _join(m.get("commit") for m in metas),
            "spartan2_rev": _join(m.get("spartan2_rev") for m in metas),
            "command": _join(m.get("command") for m in metas),
            "source_files": _join(s[0] for s in srcs), "run_ids": _join(s[1] for s in srcs),
            "measures": measures})

    def tags(self):
        return {r["table_cell"] for r in self.rows}

    def write(self, path):
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, COLUMNS)
            w.writeheader()
            w.writerows(self.rows)
