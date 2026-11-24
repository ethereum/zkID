import os
import unittest

import synth
from bench import Dataset
from compose import compose
from provenance import Prov
from tables import TABLES, Ctx, fmt_size, fmt_time, lint_tabular

HERE = os.path.dirname(os.path.abspath(__file__))
GOLDEN = os.path.join(HERE, "golden")


def synthetic_dataset():
    rows = (synth.mac_rows() + synth.bridge_rows() + synth.shape_rows() + synth.peakmem_rows()
            + synth.registry_rows() + synth.e2e_rows()
            + synth.phone_session("iPhone18,1", "ios", 0.9) + synth.phone_session("SM-S947U1", "android", 1.2))
    return Dataset.from_rows(rows, source="synthetic.jsonl")


class FormatTest(unittest.TestCase):
    def test_time(self):
        self.assertEqual(fmt_time(950.4), "950 ms")
        self.assertEqual(fmt_time(9999.4), "9999 ms")
        self.assertEqual(fmt_time(10000), "10.0 s")
        self.assertEqual(fmt_time(12345), "12.3 s")
        self.assertEqual(fmt_time(0.2), "<1 ms")

    def test_size(self):
        self.assertEqual(fmt_size(112103), "112.1 kB")
        self.assertEqual(fmt_size(431866474), "431.9 MB")
        self.assertEqual(fmt_size(None), "--")


class LintTest(unittest.TestCase):
    GOOD = "\\begin{tabular}{lrr}\n\\toprule\nA & B & C \\\\\n\\midrule\n1 & 2 & 3 \\\\\n\\bottomrule\n\\end{tabular}\n"

    def test_good(self):
        self.assertEqual(lint_tabular(self.GOOD), [])

    def test_too_few_separators(self):
        self.assertEqual(len(lint_tabular(self.GOOD.replace("1 & 2 & 3", "1 & 2"))), 1)

    def test_too_many_separators(self):
        self.assertEqual(len(lint_tabular(self.GOOD.replace("1 & 2 & 3", "1 & 2 & 3 & 4"))), 1)

    def test_multicolumn_counts_its_span(self):
        self.assertEqual(lint_tabular(self.GOOD.replace("A & B & C", "A & \\multicolumn{2}{c}{B}")), [])

    def test_escaped_ampersand_is_not_a_separator(self):
        self.assertEqual(lint_tabular(self.GOOD.replace("1 & 2 & 3", "1 \\& x & 2 & 3")), [])

    def test_p_columns_and_at_expressions(self):
        tex = "\\begin{tabular}{@{}p{3cm}r@{}}\n\\toprule\nA & B \\\\\n\\bottomrule\n\\end{tabular}\n"
        self.assertEqual(lint_tabular(tex), [])


class TableTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ds = synthetic_dataset()
        cls.ctx = Ctx(cls.ds, Prov(cls.ds))
        cls.out = {name: fn(cls.ctx) for name, fn in TABLES.items()}

    def golden(self, name):
        text = self.out[name]
        path = os.path.join(GOLDEN, name + ".tex")
        if os.environ.get("UPDATE_GOLDEN"):
            os.makedirs(GOLDEN, exist_ok=True)
            with open(path, "w") as f:
                f.write(text)
        with open(path) as f:
            self.assertEqual(text, f.read())

    def test_goldens(self):
        for name in TABLES:
            with self.subTest(name):
                self.golden(name)

    def test_all_tables_lint_and_are_fragments(self):
        for name, tex in self.out.items():
            with self.subTest(name):
                self.assertEqual(lint_tabular(tex), [])
                self.assertNotIn("\\begin{table}", tex)
                self.assertNotIn("nan", tex)

    def test_t1_values(self):
        tex = self.out["T1"]
        self.assertIn("1500 ms", tex)   # Mac witness 500 + prove 1000
        self.assertIn("1545 ms", tex)   # headline Prepare is 3% slower
        self.assertIn("1350 ms", tex)   # iPhone at 0.9
        self.assertIn("1800 ms", tex)   # Galaxy at 1.2

    def test_t1_verify_acceptance_rows(self):
        tex = self.out["T1"]
        self.assertIn("Statement check", tex)
        self.assertIn("Verify + acceptance", tex)
        self.assertIn("65 ms", tex)   # Mac verify 60 + statement_check 5

    def test_t6_cold_has_state_load_stage(self):
        self.assertIn("cold: state load (Mac: page-cache warm) & 250 ms", self.out["T6"])

    def test_t6_notes_cold_rows_whose_state_stays_in_memory(self):
        rows = [r for r in synth.mac_run("combined", d_iss=8, d_rev=20) if r.get("step") != "state_load"]
        ds = Dataset.from_rows(rows)
        compose(ds)
        tex = TABLES["T6"](Ctx(ds, Prov(ds)))
        self.assertIn("prepared state held in memory, not loaded from storage", tex)

    def test_t5b_bandwidth(self):
        tex = self.out["T5b"]
        self.assertIn("revocation: mirror, upper bound, per update at 100 updates & 0.08 kB", tex)
        self.assertIn("revocation: mirror, minimum, per update at 100 updates & 0.03 kB", tex)
        self.assertIn("revocation: proof fetch, per proof after 1 updates", tex)
        self.assertNotIn("bandwidth", self.out["T5"])

    def test_t5_keeps_methods_apart(self):
        rows = [{"kind": "REGISTRY", "registry": "revocation", "op": "import", "method": m, "population": 1024, "k": None,
                 "wall_us": us, "iter": 1, "phase": "warm"} for m, us in (("validate=true", 9000), ("validate=false", 1000))]
        ds = Dataset.from_rows(rows)
        tex = TABLES["T5"](Ctx(ds, Prov(ds)))
        self.assertIn("(validate=true) & 9 ms", tex)
        self.assertIn("(validate=false) & 1 ms", tex)

    def test_t5_prints_sub_millisecond_values_in_microseconds(self):
        rows = [{"kind": "REGISTRY", "registry": "revocation", "op": op, "population": 1024, "k": None, "wall_us": us, "iter": 1,
                 "phase": "warm", "calls": 1000, "beyond_circuit": False, "future_field": [1]}
                for op, us in (("lookup", 22.4), ("to_commitment", 4.25), ("insert", 640), ("build", 1000))]
        ds = Dataset.from_rows(rows)
        tex = TABLES["T5"](Ctx(ds, Prov(ds)))
        self.assertIn("lookup & 22\\,$\\mu$s", tex)
        self.assertIn("to commitment & 4.2\\,$\\mu$s", tex)
        self.assertIn("insert & 640\\,$\\mu$s", tex)
        self.assertIn("build & 1 ms", tex)
        self.assertNotIn("<1 ms", tex)

    def test_e2e_witness_stages_are_summed(self):
        ds = Dataset.from_rows([{"kind": "E2E", "workload": "import", "config": "combined", "platform": "macos",
                                 "product_model": "Mac15,9", "composed": True,
                                 "stages": [{"name": "witness_inputs", "wall_us": 1000, "where": "node"},
                                            {"name": "witness_gen", "wall_us": 2000, "where": "mac"},
                                            {"name": "prepare_prove", "wall_us": 3000, "where": "mac"}]}])
        self.assertIn("6 ms", TABLES["T6"](Ctx(ds, Prov(ds))))

    def test_t6_never_pools_across_k_or_population(self):
        base = [r for r in synth.e2e_rows() if r["product_model"] == "Mac15,9" and r["workload"] == "stale_root_retry"
                and r["composed"]]
        rows = [dict(r, k=k, population={"issuers": 256, "revoked": 1_046_528}, total_us=r["total_us"] * f)
                for k, f in ((1, 1.0), (1000, 3.0)) for r in base]
        rows.append(dict(base[0], k=1000, population={"issuers": 256, "revoked": 32768}, total_us=base[0]["total_us"] * 9))
        ds = Dataset.from_rows(rows)
        tex = TABLES["T6"](Ctx(ds, Prov(ds)))
        self.assertIn("stale root retry, k=1, $\\approx 2^{20}$ & 2900 ms", tex)
        self.assertIn("stale root retry, k=1000, $\\approx 2^{20}$ & 8700 ms", tex)
        self.assertIn("stale root retry, k=1000, $2^{15}$ & 26.1 s", tex)

    def test_t1b_and_t4_show_both_prove_labels(self):
        for name in ("T1b", "T4"):
            tex = self.out[name]
            self.assertIn("Show prove (incl. witness)", tex)
            self.assertIn("Show prove (witness ready)", tex)
        self.assertIn("70 ms", self.out["T4"])       # 0.6 of the 116 ms product show_prove

    def test_t1_vk_load_labels_the_mac_cache_state(self):
        self.assertIn("VK load, first iteration (Mac: page cache warm)", self.out["T1"])
        ctx = self.ctx
        mac = [r["measures"] for r in ctx.prov.rows if r["table_cell"].startswith("T1/VK load/mac")]
        phone = [r["measures"] for r in ctx.prov.rows if r["table_cell"].startswith("T1/VK load/s26plus")]
        self.assertIn("page cache warm", mac[0])
        self.assertIn("from storage", phone[0])
        self.assertNotIn("from storage", mac[0])

    def test_t2b_hardening_prepare_row_is_labelled_for_all_changes(self):
        self.assertIn("all JWT-circuit changes v1.0.0 to main", self.out["T2b"])

    def test_t8_uses_batch_reblind(self):
        self.assertIn("1 & 927 ms", self.out["T8"])
        self.assertIn("8 & 7416 ms", self.out["T8"])

    def test_t1_verify_is_pure_and_vk_rows_are_separate(self):
        tex = self.out["T1"]
        self.assertIn("Verify & 60 ms", tex)               # Mac verify, no VK load
        self.assertIn("Verify + acceptance & 65 ms", tex)  # verify 60 + statement_check 5, no double count
        self.assertIn("VK load, first iteration (Mac: page cache warm) & 20 ms", tex)
        self.assertRegex(tex, r"VK digest \(Mac only[^&]*& 100 ms \[100, 100\] & 100 ms \[100, 100\] & -- & -- & -- & -- \\")

    def test_vk_load_without_vk_loaded_is_excluded_and_noted(self):
        rows = synth.mac_run("main")
        for r in rows:
            r.pop("vk_loaded", None)
        ds = Dataset.from_rows(rows)
        ctx = Ctx(ds, Prov(ds))
        self.assertIn("VK load, first iteration (Mac: page cache warm) & -- ", TABLES["T1"](ctx))
        self.assertTrue(any("EXCLUDED vk_load" in n and "1 of 1" in n for n in ctx.notes))

    def test_vk_load_with_only_one_vk_is_excluded(self):
        rows = synth.mac_run("main")
        for r in rows:
            if r.get("step") == "vk_load":
                r["vk_loaded"] = ["prepare"]
        ds = Dataset.from_rows(rows)
        self.assertIn("VK load, first iteration (Mac: page cache warm) & -- ", TABLES["T1"](Ctx(ds, Prov(ds))))

    def test_t4_verify_column_is_pure(self):
        self.assertNotIn("80 ms", self.out["T4"])
        self.assertIn("60 ms", self.out["T4"])

    def test_t9a_with_and_without_the_linear_t_term(self):
        tex = self.out["T9a"]
        self.assertIn("$T$ & 100.0 & --", tex)
        self.assertIn("$R^2$ & 1.000000 & 0.9", tex)

    def test_t9b_structural_count_and_evidence_columns(self):
        tex = self.out["T9b"]
        self.assertIn("combined & 8 & 20 & 61 & 61.0 & 31 & 62 & -1", tex)

    def test_t2_hardening_rows(self):
        tex = self.out["T2b"]
        self.assertIn("ECDSA main $-$ v1 (device-binding hardening) & 400", tex)
        self.assertIn("including hardening and claim normalization) & 50000", tex)

    def test_t2a_matches_generic_1920_by_params(self):
        rows = [synth.shape_row("jwt", "combined", 1_504_626, matrix_id="A2", jwt_params=[1920, 1800, 4, 50, 128])]
        ds = Dataset.from_rows(rows)
        self.assertIn("1920 B & -- & -- & -- & -- & 1504626", TABLES["T2a"](Ctx(ds, Prov(ds))))

    def test_t7_pairs_by_base_cell_then_by_circuit(self):
        t1 = synth.mac_run("combined", d_iss=8, d_rev=20, matrix_id="X2", cell="x2-1t", threads_requested=1, base_cell="A1-c")
        base = synth.mac_run("combined", d_iss=8, d_rev=20, matrix_id="A1", cell="A1-c")
        other = synth.mac_run("combined", d_iss=8, d_rev=20, matrix_id="A1", cell="A1-other", scale=3)
        ds = Dataset.from_rows(t1 + other + base)
        self.assertIn("1030 ms", TABLES["T7"](Ctx(ds, Prov(ds))).split("\n")[4])
        t1[0].pop("base_cell")
        ds = Dataset.from_rows(synth.mac_run("combined", d_iss=8, d_rev=20, matrix_id="X2", cell="x2-1t",
                                             threads_requested=1) + base)
        self.assertIn("1030 ms", TABLES["T7"](Ctx(ds, Prov(ds))).split("\n")[4])

    def test_t1_labels(self):
        for label in ("OpenAC+ GP only", "OpenAC+ (8,20)"):
            self.assertIn(label, self.out["T1"])

    def test_t4_has_all_six_rows(self):
        tex = self.out["T4"]
        for label in ("OpenAC v1.0.0 (as published)", "OpenAC+ GP only", "+ issuer hiding", "+ revocation (10)",
                      "OpenAC+ (8,10) as built", "OpenAC+ (8,20)"):
            self.assertIn(label, tex)

    def test_t2_components(self):
        tex = self.out["T2b"]
        self.assertIn("19084", tex)    # base Show
        self.assertIn("59800", tex)    # per level: two compressions
        self.assertIn("9400", tex)     # ECDSA

    def test_t1_missing_cells_are_dashes(self):
        ds = Dataset.from_rows(synth.mac_run("main"))
        tex = TABLES["T1"](Ctx(ds, Prov(ds)))
        self.assertIn("--", tex)
        self.assertEqual(lint_tabular(tex), [])

    def test_empty_dataset_renders_every_table(self):
        ds = Dataset()
        for name, fn in TABLES.items():
            tex = fn(Ctx(ds, Prov(ds)))
            self.assertEqual(lint_tabular(tex), [], name)

    def test_every_number_has_provenance(self):
        tags = self.ctx.prov.tags()
        for name in ("T1", "T1b", "T4"):
            self.assertTrue(any(t.startswith(name + "/") for t in tags), name)
        for r in self.ctx.prov.rows:
            self.assertTrue(r["measures"])
            self.assertTrue(r["device"])


if __name__ == "__main__":
    unittest.main()
