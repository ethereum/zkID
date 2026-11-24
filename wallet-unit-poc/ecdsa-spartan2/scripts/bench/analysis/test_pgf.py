import csv
import math
import os
import re
import tempfile
import unittest

from figures import FIGURES, make_all
from pgf import EMITTERS, esc
from provenance import Prov
from tables import Ctx
from test_tables import synthetic_dataset

POINT = re.compile(r"\((-?[0-9.e+]+),(-?[0-9.e+]+)\)")


class COORD:
    """Coordinates only; the legend text may hold something that looks like a pair, such as (8,20)."""
    @staticmethod
    def findall(tex):
        return [m for line in tex.splitlines() if "\\addplot" in line for m in POINT.findall(line)]


def read_csv(path):
    with open(path) as f:
        return list(csv.DictReader(f))


def expected_coords(name, rows):
    """Coordinates a figure must carry, counted from the CSV rows alone; fit rows are lines, not points."""
    has = lambda r, c: r.get(c) not in (None, "")
    if name == "F1":
        return (sum(r["kind"] == "point" for r in rows)
                + sum(r["kind"] == "point" and has(r, "show_prove_ms") for r in rows)
                + sum(r["kind"] == "point_product" for r in rows))
    if name in ("F4", "F5"):
        return len(rows) + sum(has(r, "show_prove_ms") for r in rows)
    return len(rows)


class PgfTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        ds = synthetic_dataset()
        cls.made = make_all(Ctx(ds, Prov(ds)), cls.dir.name)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def tex(self, name):
        with open(os.path.join(self.dir.name, name + ".tex")) as f:
            return f.read()

    def test_every_figure_gets_a_tex(self):
        self.assertEqual(sorted(self.made), sorted(FIGURES))
        for name in FIGURES:
            self.assertTrue(os.path.exists(os.path.join(self.dir.name, name + ".tex")), name)

    def test_coordinate_count_matches_the_csv(self):
        for name in FIGURES:
            rows = read_csv(os.path.join(self.dir.name, name + ".csv"))
            self.assertEqual(len(COORD.findall(self.tex(name))), expected_coords(name, rows), name)

    def test_braces_and_environments_balance(self):
        for name in FIGURES:
            t = self.tex(name)
            self.assertEqual(t.count("{"), t.count("}"), name)
            self.assertEqual(t.count("["), t.count("]"), name)
            self.assertEqual(t.count("\\begin{axis}"), t.count("\\end{axis}"), name)
            self.assertEqual(t.count("\\begin{tikzpicture}"), 1, name)
            self.assertEqual(t.count("\\end{tikzpicture}"), 1, name)

    def test_no_nan_or_inf(self):
        for name in FIGURES:
            t = self.tex(name).lower()
            self.assertNotIn("nan", t, name)
            self.assertNotIn("inf", t, name)
            for x, y in COORD.findall(t):
                self.assertTrue(math.isfinite(float(x)) and math.isfinite(float(y)), name)

    def test_stands_alone_inside_a_figure(self):
        for name in FIGURES:
            t = self.tex(name)
            self.assertNotIn("\\documentclass", t)
            self.assertNotIn("\\input", t)
            self.assertNotIn("\\includegraphics", t)
            self.assertIn("compat=1.18", t)

    def test_legend_uses_the_paper_names(self):
        self.assertIn("\\addlegendentry{OpenAC v1.0.0}", self.tex("F3"))
        self.assertIn("\\addlegendentry{OpenAC+ (8,20)}", self.tex("F3"))
        self.assertIn("\\addlegendentry{OpenAC+ GP only}", self.tex("F4"))

    def test_nonfinite_points_are_left_out(self):
        rows = [{"config": "main", "n": 1, "constraints": float("nan"), "show_prove_ms": 2.0},
                {"config": "main", "n": 2, "constraints": 5, "show_prove_ms": None}]
        t = EMITTERS["F5"](rows)
        self.assertEqual(sorted(COORD.findall(t)), [("0", "2"), ("1", "5")])
        self.assertNotIn("nan", t.lower())

    def test_flat_series_gets_a_linear_axis(self):
        flat = [{"config": "main", "n": n, "constraints": 100 * n, "show_prove_ms": 240.0 + n} for n in (1, 2, 4)]
        t = EMITTERS["F5"](flat)
        self.assertEqual(t.count("ymode=log"), 1)
        self.assertEqual(t.count("ymin=0"), 1)

    def test_escape(self):
        self.assertEqual(esc("a_b & 5%"), "a\\_b \\& 5\\%")


if __name__ == "__main__":
    unittest.main()
