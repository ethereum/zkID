import unittest

import synth
from bench import Dataset, summarize
from checks import check_cold_skipped
from compose import BATCHES, compose
from provenance import Prov
from tables import TABLES, Ctx


def rows_for(workload, target, ds):
    return [r for r in ds.e2e if r["workload"] == workload and r["_target"] == target and r.get("composed")]


class ComposeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rows = (synth.mac_rows() + synth.phone_session("iPhone18,1", "ios", 0.9) + synth.phone_session("SM-S947U1", "android", 1.2))
        cls.ds = Dataset.from_rows(rows, source="x.jsonl")
        compose(cls.ds)
        cls.mac = cls.ds.pick("mac", "combined", "A1", d_iss=8, d_rev=20, jwt_size="2k")

    def test_warm_is_the_per_iteration_sum_of_present_verify_and_statement_check(self):
        want = summarize(self.ds.derived(self.mac, ["present_total", "verify", "statement_check"])).median
        got = summarize([r["total_us"] / 1000 for r in rows_for("warm", "mac", self.ds)]).median
        self.assertAlmostEqual(got, want, places=3)

    def test_import_is_witness_plus_prove_plus_one_reblind(self):
        want = summarize(self.ds.derived(self.mac, ["prepare_witness", "prepare_prove", "prepare_reblind"])).median
        got = summarize([r["total_us"] / 1000 for r in rows_for("import", "mac", self.ds)]).median
        self.assertAlmostEqual(got, want, places=3)

    def test_stage_lists_are_written_out(self):
        r = rows_for("warm", "mac", self.ds)[0]
        self.assertEqual([s["name"] for s in r["stages"]], ["present_total", "verify", "statement_check"])
        self.assertTrue(all(s["where"] == "mac" for s in r["stages"]))
        self.assertEqual(rows_for("warm", "s26plus", self.ds)[0]["stages"][0]["where"], "phone")
        self.assertEqual((r["composed"], r["matrix_id"]), (True, "E1"))

    def test_cold_adds_loads_once_and_the_vk_digest_on_the_mac_only(self):
        mac = rows_for("cold", "mac", self.ds)[0]
        phone = rows_for("cold", "s26plus", self.ds)[0]
        self.assertEqual([s["name"] for s in mac["stages"]],
                         ["key_load_prepare", "key_load_show", "state_load", "vk_load", "vk_digest", "present_total", "verify",
                          "statement_check"])
        self.assertNotIn("vk_digest", [s["name"] for s in phone["stages"]])
        self.assertAlmostEqual(mac["total_us"], sum(s["wall_us"] for s in mac["stages"]))

    def test_refill_is_per_tuple_reblind_times_b(self):
        phone = {r["batch"]: r for r in rows_for("refill", "s26plus", self.ds)}
        self.assertEqual(sorted(phone), list(BATCHES))
        base = summarize(self.ds.values(self.ds.pick("s26plus", "combined", "A1", d_rev=20), "prepare_reblind")).median * 1000
        self.assertAlmostEqual(phone[8]["total_us"], 8 * base, delta=8 * base * 0.01)
        mac = {r["batch"]: r for r in rows_for("refill", "mac", self.ds)}
        self.assertEqual(sorted(mac), list(BATCHES))
        self.assertGreater(mac[128]["total_us"], mac[8]["total_us"])

    def test_producer_rows_are_not_duplicated(self):
        ds = Dataset.from_rows(synth.mac_rows() + synth.e2e_rows())
        before = len([r for r in ds.e2e if r["workload"] == "warm" and r["_target"] == "mac" and r["composed"]])
        compose(ds)
        self.assertEqual(len([r for r in ds.e2e if r["workload"] == "warm" and r["_target"] == "mac" and r["composed"]]), before)

    def test_a_cell_without_state_load_composes_cold_with_the_state_in_memory(self):
        rows = [r for r in synth.mac_run("combined", d_iss=8, d_rev=20) if r.get("step") != "state_load"]
        ds = Dataset.from_rows(rows)
        compose(ds)
        cold = rows_for("cold", "mac", ds)
        self.assertTrue(cold)
        self.assertTrue(all(r["state_in_memory"] is True for r in cold))
        self.assertNotIn("state_load", [s["name"] for s in cold[0]["stages"]])
        self.assertIn("vk_load", [s["name"] for s in cold[0]["stages"]])

    def test_a_cell_with_state_load_includes_it_and_is_not_marked(self):
        phone = rows_for("cold", "s26plus", self.ds)[0]
        self.assertIn("state_load", [s["name"] for s in phone["stages"]])
        self.assertFalse(phone.get("state_in_memory"))

    def test_a_cell_missing_vk_load_is_skipped_with_an_info_line(self):
        rows = [r for r in synth.mac_run("combined", d_iss=8, d_rev=20) if r.get("step") != "vk_load"]
        ds = Dataset.from_rows(rows)
        compose(ds)
        self.assertEqual(rows_for("cold", "mac", ds), [])
        self.assertTrue(rows_for("warm", "mac", ds))
        infos = [c for c in check_cold_skipped(ds) if c.status == "info"]
        self.assertEqual(len(infos), 1)
        self.assertIn("vk_load", infos[0].detail)
        self.assertNotIn("state_load", infos[0].detail)

    def test_composed_rows_carry_provenance(self):
        r = rows_for("warm", "mac", self.ds)[0]
        self.assertEqual((r["bench_sha"], r["command"], r["spartan2_rev"]), ("bbbbbbb", "synthetic", "d687dbb"))
        self.assertEqual(r["_src"], "x.jsonl")

    def test_t6_rows_show_the_composed_workloads_and_batches(self):
        tex = TABLES["T6"](Ctx(self.ds, Prov(self.ds)))
        for want in ("refill, B=1 &", "refill, B=128 &", "import &", "warm &"):
            self.assertIn(want, tex)


if __name__ == "__main__":
    unittest.main()
