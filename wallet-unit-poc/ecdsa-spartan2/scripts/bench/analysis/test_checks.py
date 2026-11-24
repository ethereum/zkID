import unittest

import synth
from bench import Dataset
from checks import (gate_gc, gate_peakmem, gate_sessions, load_pm, check_bridge, check_composed_e2e, check_crashes, check_data, check_iqr, check_mac_drift,
                    check_phone_drift, check_product_generic, check_provenance_mix, check_r1cs_header,
                    check_registry_iqr, check_session_spread, check_sp_span, gate_phonecheck, gate_provenance,
                    gate_visits, load_matrices, render_md, run_all)

NO_DROP = {"phone": 0, "mac": 0}


def mac_proc(steps, **dev):
    rows = [synth.device(config="main", cell="c", matrix_id="A1", **dev)]
    for step, vals in steps.items():
        rows += [synth.iter_row(step, v, i) for i, v in enumerate(vals, 1)]
    return rows


def phones(steps, session, config="main"):
    return Dataset.from_rows(synth.phone_proc(steps, config=config), drop_warm=NO_DROP, session=session)


def status(checks):
    return [c.status for c in checks]


class IqrTest(unittest.TestCase):
    def test_pass_and_fail(self):
        good = Dataset.from_rows(mac_proc({"prepare_prove": [1000, 1010, 1020, 1030, 1040]}))
        bad = Dataset.from_rows(mac_proc({"prepare_prove": [800, 900, 1000, 1100, 1200]}))
        self.assertEqual(status(check_iqr(good)), ["pass"])
        r = check_iqr(bad)
        self.assertEqual(status(r), ["fail"])
        self.assertAlmostEqual(r[0].value, 0.2)

    def test_fast_steps_are_gated_too(self):
        r = check_iqr(Dataset.from_rows(mac_proc({"show_reblind": [10, 50, 90, 20, 70]})))
        self.assertEqual(status(r), ["fail"])

    def test_steps_under_40_ms_may_use_an_absolute_floor(self):
        ok = check_iqr(Dataset.from_rows(mac_proc({"show_reblind": [30, 30.5, 31, 31.5, 32]})))
        self.assertEqual(status(ok), ["pass"])        # relative 3.2%, absolute 1 ms
        ok = check_iqr(Dataset.from_rows(mac_proc({"show_reblind": [20, 20.8, 21.4, 22, 22.6]})))
        self.assertEqual(status(ok), ["pass"])        # relative 8.7% but absolute 1.2 ms
        bad = check_iqr(Dataset.from_rows(mac_proc({"show_reblind": [10, 14, 18, 22, 26]})))
        self.assertEqual(status(bad), ["fail"])       # absolute 8 ms
        slow = check_iqr(Dataset.from_rows(mac_proc({"prepare_prove": [100, 104, 108, 112, 116]})))
        self.assertEqual(status(slow), ["fail"])      # 7.4% against the 5% rule, and over 40 ms

    def test_phones_are_not_checked(self):
        self.assertEqual(check_iqr(phones({"prepare_prove": [800, 900, 1000, 1100, 1200]}, "s1")), [])


class MacDriftTest(unittest.TestCase):
    def two_passes(self, scale_last):
        second = synth.mac_run("main", scale=scale_last)
        second[0]["pass"] = 1
        return Dataset.from_rows(synth.mac_run("main") + second)

    def test_pass(self):
        r = check_mac_drift(self.two_passes(1.02))
        self.assertTrue(r)
        self.assertEqual(set(status(r)), {"info"})

    def test_fail(self):
        r = check_mac_drift(self.two_passes(1.05))
        self.assertEqual(set(status(r)), {"info"})          # reported, not a gate
        self.assertTrue(any(c.value > 0.03 for c in r))

    def test_single_pass_is_skipped(self):
        self.assertEqual(status(check_mac_drift(Dataset.from_rows(synth.mac_run("main")))), ["skip"])


class MixedPassTest(unittest.TestCase):
    def test_rows_without_pass_next_to_numbered_ones_fail_not_crash(self):
        legacy = synth.mac_run("main")
        del legacy[0]["pass"]
        r = check_mac_drift(Dataset.from_rows(legacy + synth.mac_run("main")))
        self.assertIn("fail", status(r))
        self.assertIn("without `pass`", r[0].detail)

    def test_run_all_turns_a_raising_check_into_a_fail(self):
        import checks
        orig = checks.ALL
        checks.ALL = (lambda ds: 1 / 0,)
        try:
            r = checks.run_all(Dataset())
        finally:
            checks.ALL = orig
        self.assertEqual(status(r), ["fail"])
        self.assertIn("ZeroDivisionError", r[0].detail)


class PhoneDriftTest(unittest.TestCase):
    def ds(self, first, last):
        vals = [first] * 6 + [last] * 6
        return phones({"prepare_prove": vals, "present_total": vals}, "s1")

    def test_pass(self):
        self.assertEqual(status(check_phone_drift(self.ds(1000, 1040))), ["pass", "pass"])

    def test_fail(self):
        r = check_phone_drift(self.ds(1000, 1100))
        self.assertEqual(status(r), ["fail", "fail"])
        self.assertAlmostEqual(r[0].value, 0.1)

    def test_too_few_rows_is_skipped(self):
        self.assertEqual(status(check_phone_drift(phones({"prepare_prove": [1, 2, 3]}, "s1"))), ["skip"])

    def test_ten_rows_compare_first_five_with_last_five(self):
        vals = [1000] * 5 + [1100] * 5
        r = check_phone_drift(phones({"prepare_prove": vals}, "s1"))
        self.assertEqual(status(r), ["fail"])
        self.assertAlmostEqual(r[0].value, 0.1)
        self.assertIn("first 5", r[0].detail)

    def test_nine_rows_is_skipped(self):
        self.assertEqual(status(check_phone_drift(phones({"prepare_prove": [1000] * 9}, "s1"))), ["skip"])


class SessionSpreadTest(unittest.TestCase):
    def two(self, a, b):
        ds = Dataset(NO_DROP)
        for s, v in (("s1", a), ("s2", b)):
            ds.add_rows(synth.phone_proc({"prepare_prove": [v] * 3, "present_total": [v] * 3}), session=s)
        return ds

    def test_pass(self):
        self.assertEqual(status(check_session_spread(self.two(1000, 1050))), ["pass", "pass"])

    def test_fail(self):
        r = check_session_spread(self.two(1000, 1200))
        self.assertEqual(status(r), ["fail", "fail"])
        self.assertAlmostEqual(r[0].value, 200 / 1100)

    def test_one_session_is_skipped(self):
        self.assertEqual(status(check_session_spread(phones({"prepare_prove": [1, 2]}, "s1"))), ["skip"])


class SpSpanTest(unittest.TestCase):
    def ds(self, scales):
        rows = []
        for i, s in enumerate(scales):
            rows += synth.mac_run("combined", d_iss=8, d_rev=20, matrix_id="S-P", cell=f"sp{i}", scale=s)
        return Dataset.from_rows(rows)

    def test_pass(self):
        self.assertEqual(status(check_sp_span(self.ds([1.0, 1.01, 1.02]))), ["info"])

    def test_fail(self):
        r = check_sp_span(self.ds([1.0, 1.1]))
        self.assertEqual(status(r), ["info"])
        self.assertAlmostEqual(r[0].value, 0.1, places=2)

    def test_needs_two_cells(self):
        self.assertEqual(status(check_sp_span(self.ds([1.0]))), ["skip"])


class RegistryIqrTest(unittest.TestCase):
    def ds(self, us):
        return Dataset.from_rows([{"kind": "REGISTRY", "registry": "revocation", "op": "witness_member", "population": 1024,
                                   "k": None, "wall_us": v, "iter": i, "phase": "warm"} for i, v in enumerate(us, 1)])

    def test_pass_fail_and_single_row_skipped(self):
        self.assertEqual(status(check_registry_iqr(self.ds([100000, 101000, 102000, 103000]))), ["pass"])
        self.assertEqual(status(check_registry_iqr(self.ds([100000, 150000, 200000, 250000]))), ["fail"])
        self.assertEqual(status(check_registry_iqr(self.ds([100000]))), ["skip"])

    def test_fast_operations_use_the_absolute_floor(self):
        self.assertEqual(status(check_registry_iqr(self.ds([300, 900, 1200, 1500]))), ["pass"])


class ProvenanceMixTest(unittest.TestCase):
    def test_mixed_commit_fails_and_names_the_cell(self):
        rows = synth.mac_run("main", commit="aaa") + synth.mac_run("main", commit="bbb")
        r = check_provenance_mix(Dataset.from_rows(rows))
        self.assertEqual(status(r), ["fail"])
        self.assertIn("commit", r[0].detail)

    def test_consistent_cells_pass(self):
        self.assertEqual(status(check_provenance_mix(Dataset.from_rows(synth.mac_run("main", commit="aaa")))), ["pass"])


class ProductGenericPopulationTest(unittest.TestCase):
    HEAD = [2, 2, 8, 64, 8, 20]

    def test_pairs_the_generic_cell_at_the_same_population(self):
        prod = synth.mac_run("combined", d_iss=8, d_rev=20, population={"issuers": 256, "revoked": 1_046_528})
        near = synth.mac_run("variant", d_iss=8, d_rev=20, matrix_id="S-D", cell="sd", params=self.HEAD,
                             population={"issuers": 256, "revoked": 128}, scale=5.0)
        far = synth.mac_run("variant", d_iss=8, d_rev=20, matrix_id="S-N", cell="sn", params=self.HEAD,
                            population={"issuers": 256, "revoked": 1_046_528})
        r = check_product_generic(Dataset.from_rows(prod + near + far))
        self.assertEqual(status(r), ["pass"])
        self.assertIn("S-N", r[0].subject)

    def test_no_generic_cell_at_that_population_is_a_skip(self):
        prod = synth.mac_run("combined", d_iss=8, d_rev=20, population={"issuers": 256, "revoked": 1_046_528})
        gen = synth.mac_run("variant", d_iss=8, d_rev=20, matrix_id="S-D", cell="sd", params=self.HEAD,
                            population={"issuers": 256, "revoked": 128})
        self.assertEqual(status(check_product_generic(Dataset.from_rows(prod + gen))), ["skip"])


class ProductGenericTest(unittest.TestCase):
    HEAD = [2, 2, 8, 64, 8, 20]

    def ds(self, generic_scale):
        product = synth.mac_run("combined", d_iss=8, d_rev=20, path="product")   # show_prove_only is 0.6 of show_prove
        generic = synth.mac_run("variant", d_iss=8, d_rev=20, matrix_id="S-N", cell="sn", path="generic",
                                params=self.HEAD, scale=generic_scale)
        return Dataset.from_rows(product + generic)

    def test_pass(self):
        self.assertEqual(status(check_product_generic(self.ds(1.05))), ["pass"])

    def test_fail(self):
        self.assertEqual(status(check_product_generic(self.ds(1.3))), ["fail"])

    def test_missing_generic_cell_is_skipped(self):
        self.assertEqual(status(check_product_generic(Dataset.from_rows(synth.mac_run("main")))), ["skip"])


class CrashInfoTest(unittest.TestCase):
    def test_a_crash_alone_is_reported_not_failed(self):
        rows = synth.mac_run("main") + [{"kind": "CRASH", "cell": "main-2k-0-0", "attempt": 1, "signal": 11}]
        r = check_crashes(Dataset.from_rows(rows))
        self.assertEqual(status(r), ["info"])
        self.assertIn("1 crash", r[0].detail)


class GateFailedTest(unittest.TestCase):
    def test_excluded_visits_are_listed_as_info(self):
        from checks import check_excluded_visits
        ds = Dataset.from_rows(synth.mac_run("main", gate="failed") + synth.mac_run("main"))
        r = check_excluded_visits(ds)
        self.assertEqual(status(r), ["info"])
        self.assertIn("idle gate failed", r[0].detail)


class DataProblemsTest(unittest.TestCase):
    def test_unplaceable_rows_fail(self):
        ds = Dataset.from_rows(synth.phone_proc({"verify": [1]}))
        self.assertEqual(status(check_data(ds)), ["fail"])


class FinalGatesTest(unittest.TestCase):
    def test_visits_pass_fail_and_missing(self):
        ds = Dataset.from_rows(synth.mac_run("main", passes=3, cell="A1-main-2k") + synth.mac_run("main", passes=1, cell="A1-x"))
        r = {c.subject: c.status for c in gate_visits(ds, {"A1-main-2k": 3, "A1-x": 2, "A1-gone": 1})}
        self.assertEqual(r, {"A1-main-2k": "pass", "A1-x": "fail", "A1-gone": "fail"})

    def test_matrices_are_read_from_json(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            with open(f"{d}/A1.json", "w") as f:
                json.dump({"matrix_id": "A1", "cells": [{"id": "A1-a", "visits": 6}, {"id": "A1-b", "visits": 4}]}, f)
            self.assertEqual(load_matrices(d), {"A1-a": 6, "A1-b": 4})
            self.assertEqual(load_matrices(d + "/nope"), {})

    def test_provenance_gate_fails_on_unrecorded(self):
        ok = {"table_cell": "T1/a", "bench_sha": "x", "commit": "c", "command": "cmd", "spartan2_rev": "d687dbb"}
        bad = dict(ok, table_cell="T1/b", command="unrecorded")
        self.assertEqual(status(gate_provenance([ok])), ["pass"])
        r = gate_provenance([ok, bad])
        self.assertEqual(status(r), ["fail"])
        self.assertIn("T1/b", r[0].detail)

    def test_dirty_commit_fails_the_provenance_gate(self):
        row = {"table_cell": "T1/a", "bench_sha": "x", "commit": "abc123-dirty", "command": "cmd", "spartan2_rev": "r"}
        r = gate_provenance([row])
        self.assertEqual(status(r), ["fail"])
        self.assertIn("dirty", r[0].detail)

    def test_peakmem_gate_counts_runs_per_phase(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            with open(f"{d}/PM.json", "w") as f:
                json.dump({"matrix_id": "PM", "cells": [{"id": "PM-main-2k", "cmd": "peakmem", "stage": "main/A1-main-2k",
                                                         "visits": 3, "phases": ["prepare", "present"]}]}, f)
            with open(f"{d}/A1.json", "w") as f:
                json.dump({"matrix_id": "A1", "cells": [{"id": "A1-main-2k", "cmd": "run", "visits": 6}]}, f)
            self.assertEqual(load_matrices(d), {"A1-main-2k": 6})        # PM cells are not DEVICE visits
            pm = load_pm(d)
            full = Dataset.from_rows([{"kind": "PEAKMEM", "cell": "A1-main-2k", "phase": p, "run": r}
                                      for p in ("prepare", "present") for r in range(3)])
            short = Dataset.from_rows([{"kind": "PEAKMEM", "cell": "A1-main-2k", "phase": "prepare", "run": r} for r in range(3)])
            self.assertEqual(status(gate_peakmem(full, pm)), ["pass", "pass"])
            self.assertEqual(sorted(status(gate_peakmem(short, pm))), ["fail", "pass"])

    def test_gc_gate_needs_gc_exposed_on_registry_and_e2e_rows(self):
        reg = {"kind": "REGISTRY", "registry": "revocation", "op": "insert", "population": 1, "wall_us": 1, "phase": "warm"}
        ds = Dataset.from_rows([dict(reg, gc_exposed=True)])
        self.assertEqual(status(gate_gc(ds)), ["pass"])
        ds = Dataset.from_rows([dict(reg, gc_exposed=True), dict(reg, gc_exposed=False)])
        self.assertEqual(status(gate_gc(ds)), ["fail"])
        self.assertEqual(status(gate_gc(Dataset())), ["fail"])

    def test_session_gate_counts_measured_sessions_per_device_and_config(self):
        ds = Dataset(NO_DROP)
        for s in ("s1", "s2"):
            ds.add_rows(synth.phone_proc({"verify": [1]}, config="main"), session=s)
        ds.add_rows(synth.phone_proc({"verify": [1]}, config="combined"), session="s1")
        want = {"m2q-36": {"main": 2, "combined": 2}, "iphone17pro-26-5": {"main": 3}}
        r = {c.subject: c.status for c in gate_sessions(ds, want)}
        self.assertEqual(r, {"s26plus/main": "pass", "s26plus/combined": "fail", "iphone17pro/main": "fail"})
        self.assertEqual(status(gate_sessions(ds, {})), ["fail"])

    def test_provenance_gate_fails_when_nothing_was_recorded(self):
        self.assertEqual(status(gate_provenance([])), ["fail"])

    def test_phonecheck_gate_needs_one_row_per_session(self):
        rows = synth.phone_proc({"verify": [1]}, config="main")
        ds = Dataset.from_rows(rows, session="s1", drop_warm=NO_DROP)
        self.assertEqual(status(gate_phonecheck(ds)), ["fail"])
        ds.phonechecks.append({"kind": "PHONECHECK", "device": "s26plus", "config": "main", "session": "s1",
                               "proofs_valid": True, "linked": True, "roots_match_registry": True})
        self.assertEqual(status(gate_phonecheck(ds)), ["pass"])
        ds.phonechecks[0]["roots_match_registry"] = False
        self.assertEqual(status(gate_phonecheck(ds)), ["fail"])

    def test_final_turns_skips_into_fails(self):
        ds = Dataset.from_rows(synth.mac_run("main"))
        self.assertIn("skip", status(run_all(ds)))
        left = {c.name for c in run_all(ds, final=True) if c.status == "skip"}
        self.assertLessEqual(left, {"mac_drift", "sp_span", "composed_e2e"})


class SpSpanStepTest(unittest.TestCase):
    def test_uses_show_prove_only_when_the_cell_has_it(self):
        rows = []
        for i, s in enumerate((1.0, 1.0)):
            rows += synth.mac_run("combined", d_iss=8, d_rev=20, matrix_id="S-P", cell=f"sp{i}", scale=s)
        for r in rows:
            if r["kind"] == "ITER" and r["step"] == "show_prove":
                r["wall_us"] *= (1 + 0.5 * (r["iter"] % 2))        # witness noise that show_prove_only does not see
        r = check_sp_span(Dataset.from_rows(rows))
        self.assertIn("show_prove_only", r[0].subject)
        self.assertLess(r[0].value, 0.03)


class BridgeTest(unittest.TestCase):
    def ds(self, scale):
        rows = synth.mac_run("main") + synth.mac_run("main", matrix_id="BR", cell="br", scale=scale)
        return Dataset.from_rows(rows)

    def test_pass(self):
        r = check_bridge(self.ds(1.05))
        self.assertTrue(r)
        self.assertEqual(set(status(r)), {"pass"})

    def test_fail(self):
        self.assertIn("fail", status(check_bridge(self.ds(1.2))))

    def test_verify_total_is_never_compared(self):
        rows = synth.mac_run("main") + synth.mac_run("main", matrix_id="BR", cell="br")
        for r in rows:
            if r["kind"] == "ITER" and r["step"] == "verify_total" and r["wall_us"]:
                if rows.index(r) > len(rows) // 2:
                    r["wall_us"] *= 3
        r = check_bridge(Dataset.from_rows(rows))
        self.assertNotIn("verify_total", " ".join(c.subject for c in r))
        self.assertEqual(set(status(r)), {"pass"})

    def test_a_fixture_other_than_accepted_never_reaches_the_comparison(self):
        rows = (synth.mac_run("main") + synth.mac_run("main", matrix_id="BR", cell="br", scale=1.03, fixture="over18",
                                                      fixture_expect="accept")
                + synth.mac_run("main", matrix_id="BR", cell="br", scale=5.0, fixture="untrustedIssuer",
                                fixture_expect="reject"))
        self.assertEqual(set(status(check_bridge(Dataset.from_rows(rows)))), {"pass"})

    def test_no_bridge_cells_is_skipped(self):
        self.assertEqual(status(check_bridge(Dataset.from_rows(synth.mac_run("main")))), ["skip"])


class ComposedE2eVariantTest(unittest.TestCase):
    def test_k_and_population_are_never_pooled(self):
        base = [r for r in synth.e2e_rows() if r["product_model"] == "Mac15,9" and r["workload"] == "warm"]
        rows = []
        for k, scale in ((1, 1.0), (1000, 5.0)):
            for r in base:
                rows.append(dict(r, k=k, total_us=r["total_us"] * (scale if not r["composed"] else scale)))
        self.assertEqual(status(check_composed_e2e(Dataset.from_rows(rows))), ["pass", "pass"])

    def test_missing_orchestrated_rows_stay_a_skip_even_in_final(self):
        rows = [r for r in synth.e2e_rows() if r["composed"]]
        out = run_all(Dataset.from_rows(rows), final=True)
        self.assertEqual([c.status for c in out if c.name == "composed_e2e"], ["skip"])


class ComposedE2eTest(unittest.TestCase):
    def rows(self, orch_scale):
        return [{**r, "total_us": r["total_us"] * (1 if r["composed"] else orch_scale / 1.04)}
                for r in synth.e2e_rows() if r["product_model"] == "Mac15,9" and r["workload"] == "warm"]

    def test_pass(self):
        self.assertEqual(status(check_composed_e2e(Dataset.from_rows(self.rows(1.05)))), ["pass"])

    def test_fail(self):
        self.assertEqual(status(check_composed_e2e(Dataset.from_rows(self.rows(1.25)))), ["fail"])

    def test_missing_orchestrated_is_skipped(self):
        rows = [r for r in self.rows(1.0) if r["composed"]]
        self.assertEqual(status(check_composed_e2e(Dataset.from_rows(rows))), ["skip"])

    def test_medians_not_the_last_row(self):
        base = self.rows(1.0)[0]
        rows = [dict(base, total_us=t, composed=True) for t in (1_000_000, 1_000_000, 2_000_000)]
        rows += [dict(base, total_us=1_050_000, composed=False)]
        self.assertEqual(status(check_composed_e2e(Dataset.from_rows(rows))), ["pass"])

    def test_total_ignores_overlapping_stages(self):
        from checks import e2e_total
        stages = [{"name": "present_total", "wall_us": 100}, {"name": "show_prove", "wall_us": 30},
                  {"name": "vk_load", "wall_us": 50}, {"name": "verify", "wall_us": 10}]
        self.assertEqual(e2e_total({"stages": stages}), 110)

    def test_total_falls_back_to_stage_sum(self):
        rows = self.rows(1.0)
        for r in rows:
            del r["total_us"]
        self.assertEqual(status(check_composed_e2e(Dataset.from_rows(rows))), ["pass"])


class HeaderTest(unittest.TestCase):
    def test_match_and_mismatch(self):
        ok = synth.shape_row("show", "main", 100)
        bad = synth.shape_row("jwt_1k", "main", 200, loaded_constraints=201)
        r = check_r1cs_header(Dataset.from_rows([ok, bad]))
        self.assertEqual(sorted(status(r)), ["fail", "pass"])

    def test_no_header_is_skipped(self):
        row = synth.shape_row("show", "main", 100)
        del row["loaded_constraints"], row["loaded_wires"]
        self.assertEqual(status(check_r1cs_header(Dataset.from_rows([row]))), ["skip"])


class LegacyHeaderTest(unittest.TestCase):
    def test_header_names_are_a_fallback(self):
        row = synth.shape_row("show", "main", 100)
        del row["loaded_constraints"], row["loaded_wires"]
        row.update(header_constraints=100, header_wires=200)
        self.assertEqual(status(check_r1cs_header(Dataset.from_rows([row]))), ["pass"])
        row["header_constraints"] = 101
        self.assertEqual(status(check_r1cs_header(Dataset.from_rows([row]))), ["fail"])


class CrashTest(unittest.TestCase):
    def test_counts_and_rejects(self):
        rows = synth.mac_run("main") + [{"kind": "CRASH", "cell": "main-2k-0-0", "attempt": 1, "signal": 11}]
        rows[-3]["ok"] = False
        r = check_crashes(Dataset.from_rows(rows))
        self.assertEqual(status(r), ["fail"])
        self.assertIn("1 crash", r[0].detail)
        self.assertIn("1 not-ok", r[0].detail)

    def test_done_errors_fail_the_cell(self):
        rows = synth.mac_run("main")
        rows[-1]["errors"] = 2
        r = check_crashes(Dataset.from_rows(rows))
        self.assertEqual(status(r), ["fail"])
        self.assertIn("2 errors in DONE", r[0].detail)

    def test_clean_cells_pass(self):
        self.assertEqual(status(check_crashes(Dataset.from_rows(synth.mac_run("main")))), ["pass"])


class RenderTest(unittest.TestCase):
    def test_markdown_lists_every_check(self):
        ds = Dataset.from_rows(mac_proc({"prepare_prove": [1000, 1010, 1020, 1030, 1040]}))
        md = render_md(run_all(ds), ds)
        self.assertIn("| iqr |", md)
        self.assertIn("| bridge |", md)
        self.assertIn("Rejected rows: 0", md)


if __name__ == "__main__":
    unittest.main()
