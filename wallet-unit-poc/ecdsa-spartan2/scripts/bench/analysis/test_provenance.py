import csv
import os
import tempfile
import unittest

import synth
from bench import Dataset
from provenance import COLUMNS, Prov


class ProvTest(unittest.TestCase):
    def test_cell_row_carries_shas_command_and_sources(self):
        ds = Dataset.from_rows(synth.mac_run("main"), source="bench.jsonl")
        p = Prov(ds)
        p.add("T1/x", 12.5, "mac", "prepare_prove alone", "ms", cells=[ds.cells()[0]])
        r = p.rows[0]
        self.assertEqual((r["bench_sha"], r["base_sha"], r["spartan2_rev"], r["command"]),
                         ("bbbbbbb", "aaaaaaa", "d687dbb", "synthetic"))
        self.assertEqual(r["commit"], "unrecorded")
        self.assertEqual((r["source_files"], r["run_ids"]), ("bench.jsonl", "r"))

    def test_row_source_and_unrecorded(self):
        ds = Dataset.from_rows([{"kind": "SHAPE", "circuit": "show", "constraints": 1}], source="shape.jsonl")
        p = Prov(ds)
        p.add("T2/y", 1, "mac", "show alone", rows=ds.shapes)
        self.assertEqual(p.rows[0]["source_files"], "shape.jsonl")
        self.assertEqual(p.rows[0]["bench_sha"], "unrecorded")

    def test_write_has_all_columns(self):
        p = Prov(Dataset())
        p.add("a", 1, "mac", "m")
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "p.csv")
            p.write(path)
            with open(path) as f:
                self.assertEqual(list(list(csv.DictReader(f))[0]), list(COLUMNS))


if __name__ == "__main__":
    unittest.main()
