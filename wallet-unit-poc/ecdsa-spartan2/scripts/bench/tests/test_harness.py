import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))
import layout
import peakmem
import stage_generic_all
import argparse
import make_matrices
import run_matrix
import stage
import stagelib as sl
from test_constraints import r1cs_bytes

_BENCH_ROOT = tempfile.TemporaryDirectory()
os.environ["OPENACPLUS_BENCH_ROOT"] = _BENCH_ROOT.name


class Layout(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.r1cs = os.path.join(self.tmp, "c.r1cs")
        with open(self.r1cs, "wb") as f:
            f.write(r1cs_bytes(100, 1, 4, 10, 50, 20))
        self.sym = os.path.join(self.tmp, "c.sym")

    def write_sym(self, names, idx0=10):
        with open(self.sym, "w") as f:
            f.write("1,1,0,main.expressionResult\n")
            for i, n in enumerate(names):
                f.write(f"{i + 2},{idx0 + i},0,{n}\n")
            f.write("99,-1,0,main.other\n")

    def show_names(self, rev):
        names = ["main.deviceKeyX", "main.deviceKeyY", "main.claimValues[0]", "main.claimValues[1]",
                 "main.claimIdentifierHashes[0]", "main.claimIdentifierHashes[1]", "main.issuerKeyX", "main.issuerKeyY"]
        return names + (["main.revocationCommitment[0]", "main.revocationCommitment[1]"] if rev else [])

    def test_show_layout_with_revocation_in_shared_order(self):
        self.write_sym(self.show_names(True))
        lo = layout.derive("show", self.sym, self.r1cs, 2)
        self.assertEqual(lo["shared"], list(range(10, 20)))
        self.assertEqual(lo["num_public"], 5)

    def test_revocation_group_is_optional(self):
        self.write_sym(self.show_names(False))
        self.assertEqual(len(layout.derive("show", self.sym, self.r1cs, 2)["shared"]), 8)

    def test_missing_required_signal_fails(self):
        self.write_sym(self.show_names(False)[:-1])
        with self.assertRaises(ValueError):
            layout.derive("show", self.sym, self.r1cs, 2)

    def test_removed_signal_fails(self):
        with open(self.sym, "w") as f:
            f.write("1,-1,0,main.deviceKeyX\n")
        with self.assertRaises(ValueError):
            layout.sym_indices(self.sym, ["main.deviceKeyX"])

    def test_prepare_names(self):
        names = [n for n, in [(x,) for x in ["main.KeyBindingX", "main.KeyBindingY", "main.normalizedClaimValues[0]",
                 "main.normalizedClaimValues[1]", "main.claimIdentifierHashes[0]", "main.claimIdentifierHashes[1]",
                 "main.pubKeyX", "main.pubKeyY", "main.RevocationCommitment[0]", "main.RevocationCommitment[1]"]]]
        self.write_sym(names)
        self.assertEqual(layout.derive("prepare", self.sym, self.r1cs, 2)["shared"], list(range(10, 20)))


class Gate(unittest.TestCase):
    def test_idle(self):
        self.assertEqual(run_matrix.gate_failures([(1.0, "/bin/zsh"), (20.0, "Safari")]), [])

    def test_forbidden_any(self):
        self.assertTrue(run_matrix.gate_failures([(0.0, "/usr/bin/cargo build")]))
        self.assertTrue(run_matrix.gate_failures([(0.0, "qemu-system-aarch64 -m 4g")]))

    def test_threshold_processes(self):
        self.assertEqual(run_matrix.gate_failures([(4.0, "/x/circom --wasm")]), [])
        self.assertTrue(run_matrix.gate_failures([(6.0, "/x/circom --wasm")]))
        self.assertTrue(run_matrix.gate_failures([(6.0, "gradle daemon")]))

    def test_total_cpu(self):
        self.assertTrue(run_matrix.gate_failures([(60.0, "a"), (50.0, "b")]))

    def test_needs_two_passing_checks(self):
        snaps = iter([[(0, "a")], [(0, "cargo")], [(0, "a")], [(0, "a")]])
        self.assertTrue(run_matrix.idle_gate(60, sleep=lambda s: None, snapshot=lambda: next(snaps), thermal=lambda: 0))

    def test_gate_times_out(self):
        self.assertFalse(run_matrix.idle_gate(-1, sleep=lambda s: None, snapshot=lambda: [(0, "cargo")], thermal=lambda: 0))


class Order(unittest.TestCase):
    def test_round_robin_reversed_on_odd_passes(self):
        cells = [{"id": "a", "visits": 3}, {"id": "b", "visits": 3}, {"id": "c", "visits": 2}]
        got = [(p, c["id"]) for p, c in run_matrix.visit_order(cells, 3)]
        self.assertEqual(got, [(0, "a"), (0, "b"), (0, "c"), (1, "c"), (1, "b"), (1, "a"), (2, "a"), (2, "b")])


class Retry(unittest.TestCase):
    class R:
        def __init__(self, rc, err=""):
            self.returncode, self.stderr = rc, err

    def run_it(self, codes):
        tmp = tempfile.mkdtemp()
        bench = os.path.join(tmp, "bench.jsonl")
        it = iter(codes)
        cell = {"id": "c", "stage": "x/y", "visits": 1}
        ctl = {"power": "ac", "therm": 100}

        def runner(cmd, **kw):
            out = cmd[cmd.index("--out") + 1]
            rc = next(it)
            with open(out, "w") as f:
                f.write(json.dumps({"kind": "ITER", "attempt_rc": rc}) + "\n")
            return self.R(rc, "bus error")

        kept = run_matrix.run_visit(cell, "r", 0, ctl, bench, runner=runner)
        return kept, sl.read_jsonl(bench) if os.path.exists(bench) else []

    def test_signal_kill_is_retried_and_rows_dropped(self):
        kept, rows = self.run_it([-10, -10, 0])
        self.assertTrue(kept)
        self.assertEqual([r["kind"] for r in rows], ["CRASH", "CONTROL", "CRASH", "CONTROL", "ITER"])
        self.assertEqual(rows[-1]["attempt_rc"], 0)

    def test_gives_up_after_three_crashes(self):
        kept, rows = self.run_it([-10, -10, -10])
        self.assertFalse(kept)
        self.assertEqual([r["attempt"] for r in rows if r["kind"] == "CRASH"], [1, 2, 3])

    def test_plain_failure_keeps_rows(self):
        kept, rows = self.run_it([1])
        self.assertTrue(kept)
        self.assertEqual(rows[0]["kind"], "ITER")


class Parsers(unittest.TestCase):
    def test_time_l(self):
        s = "        3.21 real         2.10 user         0.50 sys\n  734003200  maximum resident set size\n  800000000  peak memory footprint\n"
        self.assertEqual(sl.parse_time_l(s), {"max_rss_bytes": 734003200, "peak_footprint_bytes": 800000000, "wall_s": 3.21})

    def test_pmset(self):
        self.assertEqual(sl.parse_pmset_therm("CPU_Scheduler_Limit = 100\nCPU_Speed_Limit = 80"), 80)
        self.assertEqual(sl.parse_pmset_therm("No thermal warning level has been recorded"), 100)
        self.assertEqual(sl.parse_pmset_power("Now drawing from 'AC Power'"), "ac")
        self.assertEqual(sl.parse_pmset_power("Now drawing from 'Battery Power'"), "battery")
        self.assertTrue(sl.parse_low_power(" lowpowermode         1"))

    def test_otool_filter(self):
        out = "/x/bin:\n\t/usr/lib/libSystem.B.dylib (compat 1.0)\n\t/opt/a/libfr.dylib (compat 0.0)\n\t@rpath/libz.dylib (x)\n"
        self.assertEqual(stage.external_dylibs(out), ["/opt/a/libfr.dylib", "@rpath/libz.dylib"])

    def test_bundle_resolves_rpath_dependencies(self):
        import shutil
        otool = shutil.which("otool")
        if not otool:
            self.skipTest("no otool")
        tmp = tempfile.mkdtemp()
        # /bin/ls links only system libraries, so bundling it copies no dylibs.
        d = os.path.join(tmp, "cell")
        os.makedirs(d)
        self.assertEqual(stage.bundle_binary("/bin/ls", d, libdirs=[]), 0)
        self.assertTrue(os.path.exists(os.path.join(d, sl.BIN_NAME)))


class Roots(unittest.TestCase):
    roots = {"issuerRoot": str((7 << 128) + 9), "revocationRoot": str((3 << 128) + 4)}

    def expected(self, rev_hi=3):
        return {"show_public": ["1", "7", "9", str(rev_hi), "4", "x"], "prepare_public": []}

    def test_matching_roots_pass(self):
        e = stage.apply_registry_roots(self.expected(), self.roots, 20)
        self.assertEqual(e["show_public"][1:5], ["7", "9", "3", "4"])

    def test_circuit_root_mismatch_fails(self):
        with self.assertRaises(RuntimeError):
            stage.apply_registry_roots(self.expected(rev_hi=5), self.roots, 20)

    def test_revocation_root_ignored_without_tree(self):
        stage.apply_registry_roots(self.expected(rev_hi=5), self.roots, 0)


class Files(unittest.TestCase):
    def test_hardlink_shares_inode(self):
        tmp = tempfile.mkdtemp()
        src = os.path.join(tmp, "a.key")
        open(src, "w").write("k")
        store = os.path.join(tmp, "store")
        d1 = stage.stage_key(src, os.path.join(tmp, "c1", "k"), store)
        d2 = stage.stage_key(src, os.path.join(tmp, "c2", "k"), store)
        self.assertEqual(d1, d2)
        self.assertEqual(os.stat(os.path.join(tmp, "c1", "k")).st_ino, os.stat(os.path.join(tmp, "c2", "k")).st_ino)


class Matrices(unittest.TestCase):
    def test_visits_and_ids(self):
        m = make_matrices.matrices()
        ids = [c["id"] for cells in m.values() for c in cells]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(c["visits"] == 6 for c in m["A1"]))
        self.assertTrue(all(c["visits"] == 3 for c in m["X2"]))
        self.assertTrue(all(c["visits"] == 4 for k in ("A2", "S-N", "S-D", "S-P", "S-MT", "S-B", "W") for c in m[k]))
        self.assertTrue(all(c["warm"] == 5 for k, cells in m.items() if k != "PM" for c in cells))
        self.assertEqual(sum(1 for c in m["L5"] if c.get("r1cs_present")), 1)
        self.assertTrue(all(c["threads"] == 1 for c in m["X2"]))


if __name__ == "__main__":
    unittest.main()


class PathLens(unittest.TestCase):
    def write(self, obj):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "show.json")
        json.dump(obj, open(p, "w"))
        return d, p

    def test_reads_depths_as_ints_from_strings_or_lists(self):
        _, p = self.write({"issuerTreeDepth": "8", "revocationDepth": ["11"]})
        self.assertEqual(sl.path_lens(p), (8, 11))

    def test_absent_trees_are_zero(self):
        _, p = self.write({"messageHash": "1"})
        self.assertEqual(sl.path_lens(p), (0, 0))

    def test_patch_only_adds_the_fields(self):
        d, p = self.write({"issuerTreeDepth": 8, "revocationDepth": 20})
        json.dump({"cell": "c", "keys_sha256": {"k": "x"}}, open(os.path.join(d, "meta.json"), "w"))
        self.assertEqual(sl.patch_path_lens(d, p), (8, 20))
        meta = json.load(open(os.path.join(d, "meta.json")))
        self.assertEqual(meta, {"cell": "c", "keys_sha256": {"k": "x"}, "iss_path_len": 8, "rev_path_len": 20})


class Smoke(unittest.TestCase):
    cell = {"id": "c", "stage": "x/y", "visits": 1}
    ctl = {"power": "ac", "therm": 100}

    def test_smoke_output_is_not_under_runs(self):
        self.assertIn("/smoke/r1/", run_matrix.bench_path("r1", True))
        self.assertIn("/runs/r1/", run_matrix.bench_path("r1", False))

    def test_smoke_flag_reaches_the_binary_only_when_asked(self):
        on = run_matrix.build_cmd(self.cell, "r", "o", 0, self.ctl, smoke=True)[0]
        off = run_matrix.build_cmd(self.cell, "r", "o", 0, self.ctl)[0]
        self.assertIn("--smoke", on)
        self.assertNotIn("--smoke", off)

    def test_crash_rows_are_marked(self):
        tmp = tempfile.mkdtemp()
        bench = os.path.join(tmp, "b.jsonl")
        runner = lambda cmd, **kw: Retry.R(-10, "x")
        run_matrix.run_visit(self.cell, "r", 0, self.ctl, bench, runner=runner, smoke=True)
        self.assertTrue(all(r["smoke"] for r in sl.read_jsonl(bench)))


class DryRun(unittest.TestCase):
    def smoke_dir(self):
        d = tempfile.mkdtemp()
        rows = [{"kind": "CONTROL", "cell": "a"},
                {"kind": "ITER", "phase": "cold", "step": "key_load_prepare", "wall_us": 2_000_000},
                {"kind": "ITER", "phase": "warm", "step": "prepare_total", "wall_us": 1_000_000},
                {"kind": "ITER", "phase": "warm", "step": "present_total", "wall_us": 500_000},
                {"kind": "ITER", "phase": "warm", "step": "verify_total", "wall_us": 500_000},
                {"kind": "DONE"}]
        for r in rows:
            sl.append_jsonl(os.path.join(d, "s1", "bench.jsonl"), r)
        return d

    def test_estimates_and_unknown_cells(self):
        cells = [{"id": "a", "visits": 2, "warm": 5}, {"id": "b", "visits": 1, "warm": 5}]
        lines, total, unknown = run_matrix.dry_run(cells, gap=30, smoke_dir=self.smoke_dir())
        self.assertEqual(lines[0], "pass 0 a 24s")  # 2 + 6 * 2 + 10
        self.assertEqual([ln.split()[2] for ln in lines], ["a", "b", "a"])
        self.assertEqual(unknown, ["b"])
        self.assertEqual(total, 2 * (24 + 40) + (0 + 40))

    def test_stamp_commit_records_head_and_binary_hash(self):
        d = tempfile.mkdtemp()
        m, b = os.path.join(d, "meta.json"), os.path.join(d, "bin")
        json.dump({"commit": "old"}, open(m, "w"))
        open(b, "w").write("x")
        sha = stage.stamp_commit(m, os.path.dirname(os.path.abspath(__file__)), b)
        meta = json.load(open(m))
        self.assertEqual((meta["commit"], meta["bench_sha"]), (sha, sha))
        self.assertEqual(meta["binary_sha256"], sl.sha256_file(b))


class ReviewFixes(unittest.TestCase):
    def test_thermal_pressure_parse_and_gate(self):
        self.assertEqual(sl.parse_thermal_pressure("com.apple.system.thermalpressurelevel 2"), 2)
        self.assertIsNone(sl.parse_thermal_pressure("nothing"))
        self.assertTrue(run_matrix.gate_failures([(0, "a")], thermal=1))
        self.assertEqual(run_matrix.gate_failures([(0, "a")], thermal=0), [])
        snaps = [[(0, "a")]] * 4
        levels = iter([1, 0, 0, 0])
        it = iter(snaps)
        self.assertTrue(run_matrix.idle_gate(60, sleep=lambda s: None, snapshot=lambda: next(it), thermal=lambda: next(levels)))
        self.assertFalse(run_matrix.idle_gate(-1, sleep=lambda s: None, snapshot=lambda: [(0, "a")], thermal=lambda: 2))

    def test_overrides_need_smoke(self):
        ns = lambda **k: argparse.Namespace(**{"warm": None, "visits": None, "no_gate": False, "smoke": False, **k})
        run_matrix.require_smoke_for_overrides(ns())
        run_matrix.require_smoke_for_overrides(ns(warm=1, no_gate=True, smoke=True))
        for bad in (ns(warm=1), ns(visits=1), ns(no_gate=True)):
            with self.assertRaises(SystemExit):
                run_matrix.require_smoke_for_overrides(bad)

    def test_retry_waits_gates_and_writes_control(self):
        tmp = tempfile.mkdtemp()
        bench = os.path.join(tmp, "b.jsonl")
        codes = iter([-10, 0])
        slept, gated = [], []

        def runner(cmd, **kw):
            out = cmd[cmd.index("--out") + 1]
            open(out, "w").write(json.dumps({"kind": "DEVICE", "attempt": json.loads(cmd[cmd.index("--extra") + 1])["attempt"]}) + "\n")
            return Retry.R(next(codes), "x")

        run_matrix.run_visit({"id": "c", "stage": "x/y", "visits": 1}, "r", 0, {"power": "ac", "therm": 100}, bench, runner=runner, gap=30,
                             gate=lambda: gated.append(1) or True, sleep=slept.append, snapshot=lambda: {"power": "ac", "therm": 100, "thermal_pressure": 0})
        rows = sl.read_jsonl(bench)
        self.assertEqual([r["kind"] for r in rows], ["CRASH", "CONTROL", "DEVICE"])
        self.assertEqual((slept, gated), ([30], [1]))
        self.assertEqual((rows[1]["attempt"], rows[1]["idle_gate_pass"], rows[2]["attempt"]), (2, True, 2))

    def test_peakmem_provenance(self):
        prov = peakmem.provenance({"commit": "abc", "binary_sha256": "h", "d_iss": 8, "d_rev": 20, "config": "combined"}, "cmd", 18)
        row = peakmem.peak_row("cell", "combined", "prepare", 1, {"max_rss_bytes": 1}, prov)
        for k in ("commit", "binary_sha256", "command", "d_iss", "d_rev", "threads", "config"):
            self.assertIn(k, row)

    def test_generic_meta_and_cells(self):
        tmp = tempfile.mkdtemp()
        r1 = os.path.join(tmp, "a.r1cs")
        open(r1, "wb").write(b"x")
        row = {"r1cs_path": r1, "show_params": [2, 2, 8, 64, 8, 20], "population": {"issuers": 256, "revoked": 5}, "workload": "w1",
               "roots_match_circuit": True, "commit": "abc1234"}
        eco = os.path.join(tmp, "combined", "wallet-unit-poc", "ecdsa-spartan2")
        os.makedirs(eco)
        with open(os.path.join(eco, "Cargo.lock"), "w") as f:
            f.write('[[package]]\nname = "spartan2"\nversion = "0.4.0"\nsource = "git+https://example.com/Spartan2.git?branch=b#d687dbb6aaaa"\n')
        patch = mock.patch.dict(os.environ, {"OPENACPLUS_WORKTREES": tmp})
        patch.start()
        self.addCleanup(patch.stop)
        show = stage_generic_all.build_meta(row, "show", os.path.join(tmp, "none.json"))
        self.assertEqual((show["d_rev"], show["roots_source"], show["circuit_commit"]), (20, "registry", "abc1234"))
        self.assertEqual(show["spartan2_rev"], "d687dbb")
        prep = stage_generic_all.build_meta(row, "prepare", os.path.join(tmp, "none.json"))
        self.assertEqual((prep["show_params"], prep["population"], prep["workload"], prep["linked"]), (None, None, None, False))
        names = [c for r in ("A1", "S-D") for c, _, _ in stage_generic_all.cells_for({"cell": "sn_show_n2", "matrix_id": r, "workload": "w1"})]
        self.assertEqual(names, ["S-N-sn_show_n2", "S-D-sn_show_n2"])
        row = dict(row, circuit_commit="deadbee", input_sha256="aa", wtns_sha256="bb")
        self.assertEqual(stage_generic_all.build_meta(row, "show", os.path.join(tmp, "none.json"))["wtns_sha256"], "bb")
        self.assertEqual(stage_generic_all.build_meta(row, "show", os.path.join(tmp, "none.json"))["circuit_commit"], "deadbee")

    def test_every_sd_point_is_generic_and_includes_8_20(self):
        sd = make_matrices.matrices()["S-D"]
        self.assertIn("S-D-sn_show_n2", [c["id"] for c in sd])
        self.assertTrue(all(c["cmd"] == "generic" for c in sd))


class DataReviewItems(unittest.TestCase):
    def test_single_thread_cells_name_their_base_cell(self):
        x2 = make_matrices.matrices()["X2"]
        self.assertEqual({c["id"]: c["base_cell"] for c in x2},
                         {"X2-main-1t": "A1-main-2k", "X2-v1-1t": "A1-v1-2k", "X2-headline-1t": "A1-headline-2k"})
        import stage_all
        self.assertEqual(stage_all.cell_meta("X2-v1-1t"), ["--meta", json.dumps({"base_cell": "A1-v1-2k"})])
        self.assertEqual(stage_all.cell_meta("A1-v1-2k"), [])

    def test_shape_rows_use_circuit_commits(self):
        import shape_all
        self.assertEqual(shape_all.CIRCUIT_COMMIT["main"], "9557067")
        self.assertEqual(set(shape_all.CIRCUIT_COMMIT), set(shape_all.DEPTHS))


class DriverGaps(unittest.TestCase):
    def test_peakmem_smoke_paths_size_and_marking(self):
        self.assertIn("/smoke/peakmem.jsonl", peakmem.default_out(True))
        self.assertNotIn("/smoke/", peakmem.default_out(False))
        cmd = peakmem.time_cmd("b", "d", "prepare", "o", "r", "1k", smoke=True)
        self.assertEqual(cmd[cmd.index("--size") + 1], "1k")
        self.assertIn("--smoke", cmd)
        self.assertNotIn("--smoke", peakmem.time_cmd("b", "d", "prepare", "o", "r"))
        self.assertTrue(peakmem.peak_row("c", "x", "p", 1, {}, smoke=True)["smoke"])
        self.assertNotIn("smoke", peakmem.peak_row("c", "x", "p", 1, {}))

    def run_retry(self, gate_results):
        tmp = tempfile.mkdtemp()
        bench = os.path.join(tmp, "b.jsonl")
        codes = iter([-10, 0])
        slept, devices = [], []
        gates = iter(gate_results)

        def runner(cmd, **kw):
            devices.append(json.loads(cmd[cmd.index("--extra") + 1]))
            open(cmd[cmd.index("--out") + 1], "w").write("")
            return Retry.R(next(codes), "x")

        run_matrix.run_visit({"id": "c", "stage": "x/y", "visits": 1}, "r", 0, {"power": "ac", "therm": 100}, bench, runner=runner, gap=30,
                             gate=lambda: next(gates), sleep=slept.append, snapshot=lambda: {"power": "ac", "therm": 100, "thermal_pressure": 0})
        return [r for r in sl.read_jsonl(bench) if r["kind"] == "CONTROL"], slept, devices

    def test_failed_regate_waits_once_more_and_never_claims_a_pass(self):
        controls, slept, devices = self.run_retry([False, False])
        self.assertEqual([c["idle_gate_pass"] for c in controls], [False, False])
        self.assertEqual(controls[-1]["gate"], "failed")
        self.assertEqual(slept, [30, 30])
        self.assertEqual(devices[-1]["gate"], "failed")

    def test_second_regate_pass_runs_cleanly(self):
        controls, slept, devices = self.run_retry([False, True])
        self.assertEqual([c["idle_gate_pass"] for c in controls], [False, True])
        self.assertNotIn("gate", controls[-1])
        self.assertNotIn("gate", devices[-1])


class GuardGaps(unittest.TestCase):
    def ns(self, **k):
        return argparse.Namespace(**{"warm": None, "visits": None, "no_gate": False, "smoke": False, **k})

    def test_zero_overrides_still_need_smoke(self):
        for bad in (self.ns(warm=0), self.ns(visits=0)):
            with self.assertRaises(SystemExit):
                run_matrix.require_smoke_for_overrides(bad)
        run_matrix.require_smoke_for_overrides(self.ns(warm=0, visits=0, smoke=True))

    def test_unreadable_thermal_level_is_not_nominal(self):
        self.assertTrue(run_matrix.gate_failures([(0, "a")], thermal=None))
        self.assertFalse(run_matrix.idle_gate(-1, sleep=lambda s: None, snapshot=lambda: [(0, "a")], thermal=lambda: None))


class ProductParams(unittest.TestCase):
    def test_show_and_jwt_params_per_config(self):
        self.assertEqual(sl.product_params("headline", "2k"), ([2, 2, 8, 64, 8, 20], [2048, 2000, 4, 50, 128]))
        self.assertEqual(sl.product_params("main", "1k")[0], [2, 2, 8, 64])
        self.assertIsNone(sl.product_params("v1", "8k")[0])
        self.assertEqual(sl.product_params("combined", "4k")[1][0], 4096)
