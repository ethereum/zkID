"""Generic-path rows use config "variant" and a (D_iss, D_rev) tail on every show_params."""
import unittest

import synth
from bench import Dataset
from fits import depth_slope_check, per_compression
from provenance import Prov
from tables import TABLES, Ctx, cost_rows, lint_tabular
from fits import fit_cost_model


def variant(d_iss, d_rev, n=2, m=2, t=8, beta=64, matrix_id="S-D"):
    c = synth.policy_constraints(n, m, t, beta) + (2 * d_iss + 2) * synth.PER_COMPRESSION
    if d_rev:
        c += (2 * d_rev + 3) * synth.PER_COMPRESSION
    return synth.shape_row("show", "variant", c, matrix_id, [n, m, t, beta, d_iss, d_rev], "2k", d_iss, d_rev,
                           n_claims=n, m_pred=m, t_tok=t, beta=beta, constraints_kind="x")


def rows():
    out = [synth.shape_row("sha256", "variant", 30_328, matrix_id="X2", compressions=1)]
    out += [variant(8, d) for d in (8, 16, 20, 24, 32)] + [variant(d, 20) for d in (16, 24, 32)]
    for n in (2, 32):
        for m in (1, 2, 4, 16):
            for t in (1, 8, 31):
                for beta in (16, 32, 64):
                    out.append(variant(1, 0, n, m, t, beta, "X2"))
    return out


class VariantTest(unittest.TestCase):
    def setUp(self):
        self.ds = Dataset.from_rows(rows())
        self.ctx = Ctx(self.ds, Prov(self.ds))

    def test_depth_slopes_are_two_compressions_per_level(self):
        checks = {c["tree"]: c for c in depth_slope_check(self.ds)}
        self.assertAlmostEqual(checks["revocation"]["slope"], 2 * synth.PER_COMPRESSION)
        self.assertAlmostEqual(checks["issuer"]["slope"], 2 * synth.PER_COMPRESSION)
        self.assertAlmostEqual(checks["revocation"]["compressions_per_level"], 2 * synth.PER_COMPRESSION / 30_328)

    def test_cost_model_uses_the_x2_grid_at_one_depth_tail(self):
        fit = fit_cost_model(cost_rows(self.ctx))
        for k in "abcdeg":
            self.assertAlmostEqual(fit.coef[k], synth.COEF[k], places=3)
        self.assertAlmostEqual(fit.coef["f"], synth.COEF["f"] + 4 * synth.PER_COMPRESSION, places=2)

    def test_tables_see_variant_rows(self):
        self.assertIn("1842984", TABLES["T2b"](self.ctx))   # Show at (8,20)
        self.assertIn("59800", TABLES["T2b"](self.ctx))
        self.assertIn("1.97", TABLES["T9b"](self.ctx))
        for name, fn in TABLES.items():
            self.assertEqual(lint_tabular(fn(self.ctx)), [], name)


if __name__ == "__main__":
    unittest.main()
