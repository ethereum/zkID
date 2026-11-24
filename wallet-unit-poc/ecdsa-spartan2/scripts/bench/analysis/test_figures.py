import csv
import os
import tempfile
import unittest

import synth
from bench import Dataset
from figures import FIGURES, make_all
from provenance import Prov
from tables import Ctx
from test_tables import synthetic_dataset


class FigureDataTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ds = synthetic_dataset()

    def data(self, name):
        return FIGURES[name](Ctx(self.ds, Prov(self.ds)))

    def test_f1_constraints_and_times_against_depth(self):
        rows = self.data("F1")
        rev = {r["depth"]: r for r in rows if r["kind"] == "point" and r["tree"] == "revocation"}
        self.assertEqual(rev[20]["constraints"], synth.show_constraints(8, 20))
        self.assertEqual(rev[20]["padded"], 2 ** 21)
        self.assertEqual(sorted(rev), [8, 10, 16, 20, 24, 32])
        self.assertIsNotNone(rev[20]["show_prove_ms"])
        self.assertTrue(any(r["tree"] == "issuer" for r in rows))
        fits = [r for r in rows if r["kind"] == "fit_constraints" and r["tree"] == "revocation"]
        self.assertTrue(any(abs(r["slope"] - 2 * synth.PER_COMPRESSION) < 1e-6 for r in fits))

    def test_f1_time_series_is_generic_path_only(self):
        rows = self.data("F1")
        self.assertEqual({r["path"] for r in rows if r["kind"] == "point" and r["show_prove_ms"] is not None}, {"generic"})
        product = [r for r in rows if r["kind"] == "point_product"]
        self.assertEqual(sorted(r["depth"] for r in product if r["tree"] == "revocation"), [10, 20])
        self.assertEqual({r["path"] for r in product}, {"product"})
        times = [r for r in rows if r["kind"] == "fit_time"]
        self.assertTrue(times)
        for r in times:
            self.assertAlmostEqual(r["slope"], 0, places=6)   # synth is flat inside a padding class

    def test_f1_fits_use_one_population_and_annotate_it(self):
        extra = synth.mac_run("combined", d_iss=8, d_rev=12, matrix_id="S-D", population={"issuers": 200, "revoked": 99},
                              issuers=200, revoked=99, scale=9.0)
        ds = Dataset.from_rows(synth.mac_rows() + synth.shape_rows() + [synth.show_shape("combined", 8, 12, matrix_id="S-D")] + extra)
        rows = FIGURES["F1"](Ctx(ds, Prov(ds)))
        odd = [r for r in rows if r["kind"] == "point" and r["depth"] == 12 and r["tree"] == "revocation"]
        self.assertEqual((odd[0]["population"], odd[0]["fitted"]), (99, False))
        self.assertTrue(all(r["population"] == 5000 for r in rows if r["kind"] == "point" and r["fitted"]))
        for r in rows:
            if r["kind"] == "fit_time":
                self.assertAlmostEqual(r["slope"], 0, places=6)   # the 9x outlier is not in the fit

    def test_f1_fit_provenance_lists_every_contributing_cell(self):
        ctx = Ctx(self.ds, Prov(self.ds))
        rows = FIGURES["F1"](ctx)
        fit = next(r for r in rows if r["kind"] == "fit_time" and r["tree"] == "revocation")
        self.assertGreater(len(fit["_cells"]), 1)
        fitc = next(r for r in rows if r["kind"] == "fit_constraints" and r["tree"] == "revocation")
        self.assertGreater(len(fitc["_rows"]), 1)

    def test_f2_x_is_actual_path_length(self):
        rows = self.data("F2")
        self.assertEqual([r["revoked"] for r in rows], list(synth.POPULATIONS))
        self.assertEqual([r["path_len"] for r in rows], [min(20, p.bit_length()) for p in synth.POPULATIONS])

    def test_f3_sizes_in_bytes(self):
        rows = self.data("F3")
        self.assertIn(8192, {r["bytes"] for r in rows})
        self.assertLessEqual({"v1", "main", "combined"}, {r["config"] for r in rows})

    def test_f1_time_cells_come_from_the_s_d_matrix_only(self):
        cells = [synth.mac_run("combined", d_iss=8, d_rev=d, issuers=200, revoked=5000, matrix_id="S-D",
                               population={"issuers": 200, "revoked": 5000}) for d in (8, 16, 24, 32)]
        sn = synth.mac_run("variant", d_iss=8, d_rev=20, matrix_id="S-N", cell="sn_show_n2", params=[2, 2, 8, 64, 8, 20],
                           population={"issuers": 256, "revoked": 1_046_528})
        ds = Dataset.from_rows([r for c in cells for r in c] + sn + synth.shape_rows())
        rev = {r["depth"]: r for r in FIGURES["F1"](Ctx(ds, Prov(ds))) if r["kind"] == "point" and r["tree"] == "revocation"}
        self.assertIsNone(rev[20]["show_prove_ms"])
        self.assertIsNotNone(rev[16]["show_prove_ms"])

    def test_f2_uses_show_prove_only_on_product_cells(self):
        rows = FIGURES["F2"](Ctx(self.ds, Prov(self.ds)))
        cell = next(c for c in self.ds.cells() if c[2] == "S-P")
        self.assertAlmostEqual(rows[0]["show_prove_ms"], self.ds.summary(cell, "show_prove_only").median)

    def test_f3_includes_a_generic_1920_cell_staged_without_a_revocation_depth(self):
        rows = synth.mac_run("variant", d_iss=0, d_rev=0, matrix_id="A2", cell="A2-jwt_1920", path="generic",
                             params=[2, 2, 8, 64, 8, 20], jwt_params=[1920, 1800, 4, 50, 128])
        ds = Dataset.from_rows(rows)
        self.assertEqual([(r["config"], r["bytes"]) for r in FIGURES["F3"](Ctx(ds, Prov(ds)))], [("combined", 1920)])

    def test_f6_lists_path_verify_and_root_recompute(self):
        reg = [{"kind": "REGISTRY", "registry": "revocation", "op": op, "population": 1024, "k": None, "wall_us": 5,
                "iter": 1, "phase": "warm"} for op in ("path_verify", "root_recompute")]
        ds = Dataset.from_rows(reg)
        self.assertEqual({r["op"] for r in FIGURES["F6"](Ctx(ds, Prov(ds)))}, {"path_verify", "root_recompute"})

    def test_f3_generic_1920_is_found_by_jwt_params(self):
        rows = synth.mac_run("variant", d_iss=8, d_rev=20, matrix_id="A2", cell="g", path="generic",
                             params=[2, 2, 8, 64, 8, 20], jwt_params=[1920, 1800, 4, 50, 128])
        del rows[0]["jwt_size"]
        ds = Dataset.from_rows(rows)
        self.assertEqual([(r["config"], r["bytes"]) for r in FIGURES["F3"](Ctx(ds, Prov(ds)))], [("combined", 1920)])

    def test_f4_mt_pairs(self):
        rows = self.data("F4")
        self.assertEqual({(r["m"], r["t"]) for r in rows if r["config"] == "main"}, {(1, 1), (2, 8), (4, 7), (8, 15), (16, 31)})

    def test_f5_n_values(self):
        self.assertEqual(sorted({r["n"] for r in self.data("F5")}), [2, 8, 16, 32, 64])

    def test_f6_population_axis(self):
        rows = self.data("F6")
        self.assertEqual({r["population"] for r in rows}, set(synth.POPULATIONS))
        self.assertIn("witness_member", {r["op"] for r in rows})

    def test_empty_dataset_gives_empty_data(self):
        ctx = Ctx(Dataset(), Prov(Dataset()))
        for name, fn in FIGURES.items():
            self.assertEqual(fn(ctx), [], name)


class RealShapedRowsTest(unittest.TestCase):
    """Real S-P cells carry a nested population dict and no rev_path_len."""

    def ds(self, with_len=False):
        rows = []
        for i, pop in enumerate(synth.POPULATIONS):
            r = synth.mac_run("combined", d_iss=8, d_rev=20, matrix_id="S-P", cell=f"sp{i}",
                              population={"issuers": 256, "revoked": pop})
            del r[0]["revoked"], r[0]["issuers"], r[0]["rev_path_len"], r[0]["iss_path_len"]
            if with_len:
                r[0]["rev_path_len"] = min(20, pop.bit_length())
            rows += r
        return Dataset.from_rows(rows)

    def test_missing_path_length_drops_points_and_is_reported(self):
        ctx = Ctx(self.ds(), Prov(self.ds()))
        self.assertEqual(FIGURES["F2"](ctx), [])
        self.assertEqual(len(ctx.problems), 3)
        self.assertIn("rev_path_len", ctx.problems[0][1])

    def test_nested_population_is_read(self):
        ds = self.ds(with_len=True)
        rows = FIGURES["F2"](Ctx(ds, Prov(ds)))
        self.assertEqual([r["revoked"] for r in rows], list(synth.POPULATIONS))

    def test_make_all_survives_and_records_the_problem(self):
        ds = self.ds()
        ctx = Ctx(ds, Prov(ds))
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(make_all(ctx, d), [])
        self.assertTrue(ctx.problems)

    def test_one_figure_crashing_does_not_stop_the_rest(self):
        ds = synthetic_dataset()
        ctx = Ctx(ds, Prov(ds))
        import figures
        orig = figures.PLOTS["F2"]
        figures.PLOTS["F2"] = lambda *a: 1 / 0
        try:
            with tempfile.TemporaryDirectory() as d:
                made = make_all(ctx, d)
        finally:
            figures.PLOTS["F2"] = orig
        self.assertNotIn("F2", made)
        self.assertIn("F6", made)
        self.assertEqual([p[0] for p in ctx.problems if len(p) > 2], ["F2"])


class SkippedTest(unittest.TestCase):
    def test_empty_figures_are_logged(self):
        ds = Dataset()
        ctx = Ctx(ds, Prov(ds))
        with tempfile.TemporaryDirectory() as d:
            make_all(ctx, d)
        self.assertEqual(ctx.skipped, list(FIGURES))


class MakeAllTest(unittest.TestCase):
    def test_writes_csv_pdf_and_provenance(self):
        ds = synthetic_dataset()
        ctx = Ctx(ds, Prov(ds))
        with tempfile.TemporaryDirectory() as d:
            made = make_all(ctx, d)
            self.assertEqual(sorted(made), sorted(FIGURES))
            for name in FIGURES:
                with open(os.path.join(d, name + ".csv")) as f:
                    self.assertTrue(list(csv.DictReader(f)))
                self.assertGreater(os.path.getsize(os.path.join(d, name + ".pdf")), 1000)
        tags = ctx.prov.tags()
        for name in FIGURES:
            self.assertTrue(any(t.startswith(name + "/") for t in tags), name)


if __name__ == "__main__":
    unittest.main()
