import unittest

import synth
from bench import Dataset
from fits import (fit_by_class, fit_cost_model, hash_count_check, linfit, next_pow2, padding_class,
                  per_compression, per_level)


class LinfitTest(unittest.TestCase):
    def test_next_pow2(self):
        self.assertEqual([next_pow2(n) for n in (1, 2, 3, 524288, 524289)], [1, 2, 4, 524288, 1048576])

    def test_exact(self):
        f = linfit([1, 2, 3], [5, 7, 9])
        self.assertAlmostEqual(f.slope, 2)
        self.assertAlmostEqual(f.intercept, 3)
        self.assertAlmostEqual(f.r2, 1)

    def test_least_squares(self):
        f = linfit([0, 1, 2, 3], [1, 3, 2, 5])
        self.assertAlmostEqual(f.slope, 1.1)
        self.assertAlmostEqual(f.intercept, 1.1)

    def test_needs_two_distinct_x(self):
        self.assertIsNone(linfit([1], [1]))
        self.assertIsNone(linfit([2, 2], [1, 3]))

    def test_padding_class_prefers_padded_field(self):
        self.assertEqual(padding_class({"constraints": 600_000}), 1_048_576)
        self.assertEqual(padding_class({"constraints": 600_000, "padded_constraints": 786_432}), 786_432)


class ClassFitTest(unittest.TestCase):
    def pts(self):
        out = []
        for d in range(4, 33, 4):
            c = synth.show_constraints(8, d)
            out.append((d, c, c, c))
        return out

    def test_splits_at_padding_step_and_recovers_slope(self):
        pts = self.pts()
        fits = fit_by_class([(d, c, padding_class({"constraints": c})) for d, c, _, _ in pts])
        self.assertGreater(len(fits), 1)
        for cls, f in fits.items():
            if f:
                self.assertAlmostEqual(f.slope, 2 * synth.PER_COMPRESSION)

    def test_flat_time_inside_a_class(self):
        pts = [(d, 7.0, next_pow2(synth.show_constraints(8, d))) for d in range(4, 33, 4)]
        for f in fit_by_class(pts).values():
            if f:
                self.assertAlmostEqual(f.slope, 0)

    def test_singleton_class_has_no_fit(self):
        fits = fit_by_class([(1, 10, 128), (2, 20, 128), (3, 30, 8192)])
        self.assertIsNotNone(fits[128])
        self.assertIsNone(fits[8192])


class PerLevelTest(unittest.TestCase):
    def test_per_level_from_shapes(self):
        ds = Dataset.from_rows(synth.shape_rows())
        rows = [r for r in ds.shape_rows("show", config="combined") if r["d_iss"] == 8 and r["d_rev"] >= 8
                and r["show_params"][:4] == [2, 2, 8, 64]]
        slope = per_level(rows, "d_rev")
        self.assertAlmostEqual(slope["fit"].slope, 2 * synth.PER_COMPRESSION)


class PerLevelIssuerTest(unittest.TestCase):
    def test_issuer_depth_slope(self):
        ds = Dataset.from_rows(synth.shape_rows())
        rows = [r for r in ds.shape_rows("show", config="combined") if r["d_rev"] == 20
                and r["show_params"][:4] == [2, 2, 8, 64]]
        lv = per_level(rows, "d_iss")
        self.assertGreaterEqual(len(rows), 4)
        self.assertAlmostEqual(lv["fit"].slope, 2 * synth.PER_COMPRESSION)
        self.assertAlmostEqual(lv["fit"].r2, 1.0)


class CostModelTest(unittest.TestCase):
    def grid(self, noise=0):
        rows = []
        for n in (2, 8, 16, 32):
            for m in (1, 2, 4, 8, 16):
                for t in (1, 8, 15, 31):
                    for beta in (16, 32, 64, 128):
                        c = synth.policy_constraints(n, m, t, beta)
                        rows.append({"n_claims": n, "m_pred": m, "t_tok": t, "beta": beta, "constraints": c + noise})
        return rows

    def test_recovers_known_coefficients(self):
        fit = fit_cost_model(self.grid())
        for k, v in synth.COEF.items():
            self.assertAlmostEqual(fit.coef[k], v, places=4, msg=k)
        self.assertAlmostEqual(fit.r2, 1.0)
        self.assertLess(max(abs(r) for r in fit.residuals), 1e-4)

    def test_without_the_linear_t_term_the_leading_coefficients_are_biased(self):
        fit = fit_cost_model(self.grid(), with_t=False)
        self.assertNotIn("g", fit.coef)
        self.assertGreater(abs(fit.coef["c"] - synth.COEF["c"]), 1.0)
        self.assertLess(fit.r2, 1.0)

    def test_rank_deficient_grid_raises(self):
        rows = [r for r in self.grid() if r["n_claims"] == 2]
        with self.assertRaises(ValueError):
            fit_cost_model(rows)


class HashCountTest(unittest.TestCase):
    def setUp(self):
        self.ds = Dataset.from_rows(synth.shape_rows())
        self.rows = {(r["config"], r["d_iss"], r["d_rev"]): r for r in hash_count_check(self.ds)}

    def test_per_compression_from_standalone_gadget(self):
        self.assertEqual(per_compression(self.ds), synth.PER_COMPRESSION)

    def test_per_compression_divides_by_compressions(self):
        ds = Dataset.from_rows([synth.shape_row("sha256", "main", 59800, matrix_id="X2", compressions=2)])
        self.assertEqual(per_compression(ds), 29900)

    def test_combined_structural_count(self):
        r = self.rows[("combined", 8, 20)]
        self.assertEqual(r["measured"], 2 * 8 + 2 + 2 * 20 + 3)
        self.assertEqual(r["paper_hashes"], 8 + 20 + 3)
        self.assertEqual(r["paper_compressions"], 62)
        self.assertEqual(r["diff"], -1)

    def test_constraint_ratio_is_a_separate_evidence_column(self):
        self.assertAlmostEqual(self.rows[("combined", 8, 20)]["evidence"], 61.0)

    def test_single_tree_configs_have_their_own_entry_hashes(self):
        iss, rev = self.rows[("issuer", 8, 0)], self.rows[("revocation", 0, 10)]
        self.assertEqual((iss["measured"], iss["paper_hashes"], iss["diff"]), (18, 9, 0))
        self.assertEqual((rev["measured"], rev["paper_hashes"], rev["diff"]), (23, 12, -1))

    def test_structural_count_needs_no_gp_base(self):
        rows = [r for r in synth.shape_rows() if r["config"] != "main"]
        out = {(r["config"], r["d_iss"], r["d_rev"]): r for r in hash_count_check(Dataset.from_rows(rows))}
        self.assertEqual(out[("combined", 8, 20)]["measured"], 61)
        self.assertIsNone(out[("combined", 8, 20)]["evidence"])


if __name__ == "__main__":
    unittest.main()
