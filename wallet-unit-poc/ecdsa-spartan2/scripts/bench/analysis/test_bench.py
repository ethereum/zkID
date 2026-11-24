import os
import unittest

import synth
from bench import Dataset, summarize

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures")
NO_DROP = {"phone": 0, "mac": 0}


class StatsTest(unittest.TestCase):
    def test_hand_computed(self):
        s = summarize([5, 1, 3, 2, 4])
        self.assertEqual((s.median, s.p25, s.p75, s.min, s.max, s.n), (3, 2, 4, 1, 5, 5))

    def test_even_count_interpolates(self):
        s = summarize([1, 2, 3, 4])
        self.assertEqual((s.median, s.p25, s.p75), (2.5, 1.75, 3.25))

    def test_single_value(self):
        s = summarize([7])
        self.assertEqual((s.median, s.p25, s.p75, s.n), (7, 7, 7, 1))

    def test_empty(self):
        self.assertIsNone(summarize([]))


class DerivedTest(unittest.TestCase):
    def test_sum_per_iteration_then_median(self):
        rows = synth.phone_proc({"show_prove": [1, 2, 3, 4, 100], "show_reblind": [100, 3, 2, 1, 4]})
        ds = Dataset.from_rows(rows, drop_warm=NO_DROP)
        cell = ds.cells()[0]
        sums = ds.derived(cell, ["show_prove", "show_reblind"])
        self.assertEqual(sums, [101, 5, 5, 5, 104])
        self.assertEqual(summarize(sums).median, 5)
        medians = summarize(ds.values(cell, "show_prove")).median + summarize(ds.values(cell, "show_reblind")).median
        self.assertEqual(medians, 6)

    def test_iteration_missing_a_part_is_skipped(self):
        ds = Dataset.from_rows(synth.phone_proc({"a": [1, 2, 3], "b": [10, 20]}), drop_warm=NO_DROP)
        self.assertEqual(ds.derived(ds.cells()[0], ["a", "b"]), [11, 22])

    def test_iterations_of_different_processes_do_not_mix(self):
        rows = synth.phone_proc({"a": [1, 2]}) + synth.phone_proc({"b": [10, 20]})
        ds = Dataset.from_rows(rows, drop_warm=NO_DROP)
        self.assertEqual(ds.derived(ds.cells()[0], ["a", "b"]), [])


class ParserTest(unittest.TestCase):
    def test_phone_drops_first_two_warm_by_default(self):
        ds = Dataset.from_rows(synth.phone_proc({"prepare_prove": [10, 20, 30, 40, 50]}))
        self.assertEqual(ds.values(ds.cells()[0], "prepare_prove"), [30, 40, 50])

    def test_mac_keeps_all_warm_by_default(self):
        ds = Dataset.from_rows(synth.mac_run("main"))
        self.assertEqual(len(ds.values(ds.cells()[0], "prepare_prove")), 5)

    def test_cold_reported_separately(self):
        ds = Dataset.from_rows(synth.mac_run("main"))
        cell = ds.cells()[0]
        self.assertEqual(len(ds.values(cell, "prepare_prove", phase="cold")), 1)
        self.assertEqual(len(ds.values(cell, "prepare_prove")), 5)

    def test_not_ok_rows_counted_and_excluded(self):
        rows = synth.phone_proc({"prepare_prove": [10, 20, 30, 40, 50]})
        rows[-1]["ok"] = False
        ds = Dataset.from_rows(rows, drop_warm=NO_DROP)
        self.assertEqual(ds.values(ds.cells()[0], "prepare_prove"), [10, 20, 30, 40])
        self.assertEqual(len(ds.rejected), 1)

    def test_crash_rows_counted_per_cell(self):
        rows = synth.mac_run("main") + [{"kind": "CRASH", "cell": "main-2k-0-0", "attempt": 1, "signal": 11}]
        ds = Dataset.from_rows(rows)
        self.assertEqual(ds.crash_counts(), {"main-2k-0-0": 1})

    def test_key_shape(self):
        ds = Dataset.from_rows(synth.mac_run("combined", d_iss=8, d_rev=20, matrix_id="A1"))
        self.assertIn(("mac", "combined", "A1", "combined-2k-8-20", "prepare_prove", "warm"), ds.series)

    def test_matrix_id_separates_cells(self):
        rows = synth.mac_run("combined", matrix_id="A1", cell="c") + synth.mac_run("combined", matrix_id="S-P", cell="c")
        self.assertEqual(len(Dataset.from_rows(rows).cells()), 2)

    def test_threads_variant_gets_its_own_cell(self):
        ds = Dataset.from_rows(synth.mac_run("main") + synth.mac_run("main", threads_requested=1))
        self.assertEqual(sorted(c[3] for c in ds.cells()), ["main-2k-0-0", "main-2k-0-0+t1"])

    def test_phone_without_config_is_never_defaulted(self):
        ds = Dataset.from_rows(synth.phone_proc({"prepare_prove": [1]}))
        self.assertEqual(ds.cells()[0][:3], ("s26plus", "unknown", "A1"))
        self.assertEqual(len(ds.problems), 1)
        self.assertIn("config", ds.problems[0][1])

    def test_legacy_default_config_is_explicit(self):
        ds = Dataset(NO_DROP)
        ds.add_rows(synth.phone_proc({"prepare_prove": [1]}), default_config="main")
        self.assertEqual(ds.cells()[0][1], "main")
        self.assertEqual(ds.problems, [])

    def test_error_row_rejects_that_iteration_everywhere(self):
        rows = synth.phone_proc({"present_total": [1, 2, 3, 4, 5], "verify": [10, 20, 30, 40, 50]}, config="main")
        rows.append({"kind": "ERROR", "step": "verify", "iter": 3, "message": "invalid: issuer not trusted"})
        ds = Dataset.from_rows(rows, drop_warm=NO_DROP)
        cell = ds.cells()[0]
        self.assertEqual(ds.values(cell, "present_total"), [1, 2, 4, 5])
        self.assertEqual(ds.values(cell, "verify"), [10, 20, 40, 50])
        self.assertEqual(len(ds.rejected), 2)

    def test_error_row_only_hits_its_own_process(self):
        a = synth.phone_proc({"verify": [1, 2, 3]}, config="main") + [{"kind": "ERROR", "step": "verify", "iter": 2}]
        b = synth.phone_proc({"verify": [4, 5, 6]}, config="main")
        ds = Dataset.from_rows(a + b, drop_warm=NO_DROP)
        self.assertEqual(sorted(ds.values(ds.cells()[0], "verify")), [1, 3, 4, 5, 6])

    def test_vk_loaded_is_kept_on_the_observation(self):
        rows = synth.phone_proc({"vk_load": [5]}, config="main")
        rows[-1]["vk_loaded"] = ["prepare", "show"]
        ds = Dataset.from_rows(rows, drop_warm=NO_DROP)
        self.assertEqual(ds.obs(ds.cells()[0], "vk_load")[0].vk, ["prepare", "show"])

    def test_mixed_commit_or_hash_in_one_cell_is_reported(self):
        a = synth.mac_run("main", commit="aaa", r1cs_sha256="x")
        b = synth.mac_run("main", commit="bbb", r1cs_sha256="x")
        ds = Dataset.from_rows(a + b)
        self.assertEqual(list(ds.mixed(ds.cells()[0])), ["commit"])
        self.assertEqual(Dataset.from_rows(a + a).mixed(ds.cells()[0]), {})

    def test_rows_after_settle_are_excluded(self):
        rows = synth.phone_proc({"prepare_prove": [10, 11, 12]})
        rows.append({"kind": "ITER", "step": "prepare_prove", "wall_us": 0, "phase": "settle", "iter": 0, "ok": True})
        rows.append({"kind": "ITER", "step": "prepare_prove", "wall_us": 90000, "phase": "warm", "iter": 1, "ok": True})
        ds = Dataset.from_rows(rows, drop_warm=NO_DROP)
        self.assertEqual(ds.values(ds.cells()[0], "prepare_prove"), [10, 11, 12])
        self.assertEqual(ds.excluded, 1)

    def test_session_and_sources_kept(self):
        ds = Dataset.from_rows(synth.phone_proc({"prepare_prove": [1, 2, 3]}), session="s1", source="a.jsonl")
        self.assertEqual({o.session for o in ds.series[ds.cells()[0] + ("prepare_prove", "warm")]}, {"s1"})
        self.assertIn(("a.jsonl", "r"), ds.sources(ds.cells()[0]))

    def test_smoke_rows_are_skipped_unless_asked(self):
        rows = [{"kind": "REGISTRY", "registry": "issuer", "op": "build", "smoke": True, "wall_us": 1}]
        self.assertEqual(Dataset.from_rows(rows).registry, [])
        ds = Dataset(include_smoke=True)
        ds.add_rows(rows)
        self.assertEqual(len(ds.registry), 1)

    def test_visits_with_a_failed_idle_gate_are_excluded_and_counted(self):
        good = synth.mac_run("main", gate="passed")
        bad = synth.mac_run("main", gate="failed")
        ds = Dataset.from_rows(good + bad)
        self.assertEqual(len(ds.metas[ds.cells()[0]]), 1)
        self.assertEqual(len(ds.values(ds.cells()[0], "prepare_prove")), 5)
        self.assertEqual([(c[3], s) for c, s in ds.excluded_visits], [("main-2k-0-0", "idle gate failed")])

    def test_rejected_fixtures_are_excluded_and_reported(self):
        ds = Dataset.from_rows(synth.mac_run("main", fixture="over18", fixture_expect="accept")
                               + synth.mac_run("main", fixture="untrustedIssuer", fixture_expect="reject"))
        self.assertEqual(len(ds.metas[ds.cells()[0]]), 1)
        self.assertIn("fixture untrustedIssuer, expected to be rejected", ds.excluded_visits[0][1])

    def test_a_fixture_without_fixture_expect_is_not_counted_as_accepted(self):
        ds = Dataset.from_rows(synth.mac_run("main", fixture="over18"))
        self.assertEqual(ds.metas, {})
        self.assertIn("no fixture_expect", ds.excluded_visits[0][1])

    def test_rows_with_neither_field_are_accepted(self):
        self.assertEqual(len(Dataset.from_rows(synth.mac_run("main")).cells()), 1)

    def test_mixed_inputs_population_or_binary_in_one_cell_are_reported(self):
        for key, a, b in (("input_sha256", "x", "y"), ("wtns_sha256", "x", "y"), ("binary_sha256", "x", "y"),
                          ("circuit_commit", "x", "y"), ("population", {"revoked": 1}, {"revoked": 2})):
            ds = Dataset.from_rows(synth.mac_run("main", **{key: a}) + synth.mac_run("main", **{key: b}))
            self.assertIn(key, ds.mixed(ds.cells()[0]), key)

    def test_shape_rows_collected(self):
        ds = Dataset.from_rows([{"kind": "SHAPE", "circuit": "show", "config": "main", "constraints": 5},
                                {"kind": "CONSTRAINTS", "circuit": "show", "config": "main", "constraints": 5}])
        self.assertEqual(len(ds.shapes), 2)


class FixtureTest(unittest.TestCase):
    def test_emulator_fixture_parses(self):
        ds = Dataset.load([os.path.join(FIX, "emulator_bench.jsonl")])
        self.assertTrue(ds.cells())

    def test_phase1_s26plus_reproduces_results_md(self):
        ds = Dataset.load([os.path.join(FIX, "p1_s26plus.jsonl")], drop_warm=NO_DROP, default_config="main")
        cell = ds.cells()[0]
        self.assertEqual(cell[0], "s26plus")
        got = {s: summarize(ds.values(cell, s)).median for s in
               ("prepare_witness", "prepare_prove", "prepare_total", "show_prove", "prepare_reblind",
                "show_reblind", "present_total", "verify", "verify_total")}
        want = {"prepare_witness": 515.5, "prepare_prove": 1019.5, "prepare_total": 1554.4, "show_prove": 158.3,
                "prepare_reblind": 991.2, "show_reblind": 44.7, "present_total": 1223.3, "verify": 206.9,
                "verify_total": 853.7}
        for step, ms in want.items():
            self.assertAlmostEqual(got[step], ms, delta=0.06, msg=step)

    def test_phase1_iphone_reproduces_results_md(self):
        ds = Dataset.load([os.path.join(FIX, "p1_iphone.jsonl")], drop_warm=NO_DROP, default_config="main")
        cell = ds.cells()[0]
        self.assertEqual(cell[0], "iphone17pro")
        self.assertAlmostEqual(summarize(ds.values(cell, "prepare_prove")).median, 851.7, delta=0.06)
        self.assertAlmostEqual(summarize(ds.values(cell, "present_total")).median, 891.0, delta=0.06)

    def test_phase1_flow_bytes_and_sizes(self):
        ds = Dataset.load([os.path.join(FIX, "p1_s26plus.jsonl")], default_config="main")
        cell = ds.cells()[0]
        self.assertEqual(ds.flow[cell]["prepare_proof_bytes"], 112103)
        self.assertEqual(ds.sizes[cell]["2k_prepare_proving.key"], 431866474)

    def test_new_phone_layout_routes_by_device_row(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            for run in ("run1", "run2"):
                rows = synth.phone_session("SM-S947U1", "android", 1.2)
                synth.write_jsonl(os.path.join(d, "mobile", "p2", "openacplus", run, "m2q-36", "raw", "execution-000",
                                               "artifacts", "bench.jsonl"), rows)
            ds = Dataset.load_root(d)
        cells = [c for c in ds.cells() if c[0] == "s26plus"]
        self.assertEqual({c[1:3] for c in cells}, {("main", "A1"), ("combined", "A1")})
        sessions = {o.session for k, v in ds.series.items() if k[0] == "s26plus" for o in v}
        self.assertEqual(sessions, {"run1", "run2"})

    def test_load_root_globs_e2e_bridge_rows_and_skips_smoke_and_stubs(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            e = {"kind": "E2E", "workload": "warm", "config": "combined", "platform": "macos", "product_model": "Mac15,9",
                 "composed": True, "total_us": 5}
            synth.write_jsonl(os.path.join(d, "e2e", "e2e-final.jsonl"), [e, dict(e, stub=True, total_us=6)])
            synth.write_jsonl(os.path.join(d, "e2e", "e2e-smoke-x.jsonl"), [dict(e, total_us=7)])
            synth.write_jsonl(os.path.join(d, "e2e", "registry", "nested.jsonl"), [dict(e, total_us=8)])
            br = synth.mac_run("main", matrix_id="BR", cell="br", harness="bench_host")
            synth.write_jsonl(os.path.join(d, "mobile", "p2", "openacplus", "r1", "m2q-36", "bench-br.jsonl"), br)
            synth.write_jsonl(os.path.join(d, "mobile", "smoke", "a", "bench.jsonl"), synth.mac_run("main", cell="smk"))
            synth.write_jsonl(os.path.join(d, "laptop", "smoke", "x", "bench.jsonl"),
                              synth.mac_run("main", cell="smk2", smoke=True))
            ds = Dataset.load_root(d)
            self.assertEqual(sorted(r["total_us"] for r in ds.e2e), [5, 8])
            self.assertEqual({c[3] for c in ds.cells()}, {"br"})
            ds = Dataset.load_root(d, include_smoke=True)
            self.assertIn("smk2", {c[3] for c in ds.cells()})
            self.assertEqual(sorted(r["total_us"] for r in ds.e2e), [5, 6, 7, 8])
            self.assertIn("smk", {c[3] for c in ds.cells()})

    def test_load_root_reads_mac_and_phone_trees(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            synth.write_root(d)
            ds = Dataset.load_root(d)
        self.assertTrue(ds.peakmem)
        self.assertTrue(ds.shapes)
        self.assertTrue(ds.registry)
        self.assertEqual({c[0] for c in ds.cells()}, {"mac", "s26plus", "iphone17pro"})


if __name__ == "__main__":
    unittest.main()
