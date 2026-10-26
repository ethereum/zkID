import contextlib
import csv
import io
import json
import os
import tempfile
import unittest

import parse_ftl_bench as p

PREFIX = "10-26 14:03:11.512  8123  8150 I flutter : "

DEVICE = {
    "soc_model": "Tensor G4",
    "soc_manufacturer": "Google",
    "product_model": "Pixel 9",
    "manufacturer": "Google",
    "android_sdk": 35,
    "mem_total_kb": 8 * 1024 * 1024,
    "cpu_max_freq_khz": [3105000, 2600000, 2600000, 2600000, 1950000, 1950000, 1950000, 1700000],
    "big_cores": [0, 1, 2, 3],
    "rayon_default_threads": 8,
}

SIZES = {
    "jwt_proving_key_bytes": 250_000_000,
    "jwt_verifying_key_bytes": 1_500_000,
    "show_proving_key_bytes": 40_000_000,
    "show_verifying_key_bytes": 900_000,
    "jwt_proof_bytes": 300_000,
    "show_proof_bytes": 150_000,
    "jwt_witness_bytes": 8_000_000,
    "show_witness_bytes": 2_000_000,
}

STEPS = [
    "jwt_setup", "show_setup", "generate_blinds", "prove_jwt", "reblind_jwt",
    "prove_show", "reblind_show", "verify_jwt", "verify_show",
]


def line(marker, payload):
    return f"{PREFIX}{marker} {json.dumps(payload)}"


def device_line(**over):
    return line("OPENAC_DEVICE", {**DEVICE, **over})


def sizes_line(config):
    return line("OPENAC_SIZES", {"config": config, **SIZES})


def bench_line(config, it, warmup=False, **over):
    row = {"config": config, "iter": it, "warmup": warmup, "num_threads": 4,
           "pin_big_cores": True, "rss_per_step": False}
    for s in STEPS:
        row[f"{s}_ms"] = 100
        row[f"peak_rss_{s}_kb"] = 1024 * 512
    row.update(over)
    return line("OPENAC_BENCH", row)


def done_line(ok_a=3, ok_b=2, errors=0):
    return line("OPENAC_DONE", {"ok_a": ok_a, "ok_b": ok_b, "errors": errors})


def complete_fixture():
    lines = ["10-26 14:03:00.000   100   100 D noise : unrelated", device_line(), sizes_line("A")]
    lines.append(bench_line("A", 0, warmup=True, prove_jwt_ms=9999))
    for i, v in enumerate([1000, 2000, 3000], start=1):
        lines.append(bench_line("A", i, prove_jwt_ms=v, prove_show_ms=500 + i,
                                peak_rss_prove_jwt_kb=1024 * 1024 * i))
    lines.append(sizes_line("B"))
    lines.append(bench_line("B", 0, warmup=True, prove_jwt_ms=8888))
    for i, v in enumerate([3000, 5000], start=1):
        lines.append(bench_line("B", i, prove_jwt_ms=v))
    lines.append(done_line())
    return lines


PROD_RSS_MIB = {  # step: (base, peak) in MiB; prove steps get per-iteration peaks below
    "prove_jwt": (1000, 2000), "reblind_jwt": (500, 600), "prove_show": (900, 1500),
    "reblind_show": (500, 560), "verify_jwt": (550, 650), "verify_show": (500, 580),
}


def prod_line(it, rss_per_step=True, **over):
    row = {"iter": it, "rss_per_step": rss_per_step,
           "prove_jwt_ms": [4000, 6000, 5000][it - 1],
           "reblind_jwt_ms": 10, "prove_show_ms": 700 + it, "reblind_show_ms": 20,
           "verify_jwt_wall_ms": 30, "verify_show_wall_ms": 40}
    for step, (base, peak) in PROD_RSS_MIB.items():
        bump = {"prove_jwt": 100 * it, "prove_show": 50 * it}.get(step, 0)
        row[f"base_rss_{step}_kb"] = 1024 * base
        row[f"peak_rss_{step}_kb"] = 1024 * (peak + bump)
    row.update(over)
    return line("OPENAC_PROD", row)


def prod_fixture(rss_per_step=True):
    lines = [device_line()] + [prod_line(i, rss_per_step) for i in (1, 2, 3)]
    rest = [l for l in complete_fixture() if "OPENAC_DEVICE" not in l and "OPENAC_DONE" not in l]
    done = line("OPENAC_DONE", {"ok_p": 3, "ok_a": 3, "ok_b": 2, "errors": 0})
    return lines + rest + [done]


class FtlTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = self._tmp.name

    def write_logcat(self, device_dir, lines, name="logcat"):
        d = os.path.join(self.root, device_dir, "artifacts") if device_dir else self.root
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, name)
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")
        return path

    def run_main(self, *args):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = p.main(list(args))
        self.assertEqual(rc, 0)
        return buf.getvalue()

    def read(self, name, out_dir=None):
        with open(os.path.join(out_dir or self.root, name)) as f:
            return f.read()


class CompleteDeviceTest(FtlTestCase):
    def setUp(self):
        super().setUp()
        self.write_logcat("akita-35-en-portrait", complete_fixture())
        self.stdout = self.run_main(self.root)
        self.md = self.read("bench_summary.md")

    def test_csv_header_and_rows(self):
        with open(os.path.join(self.root, "bench_iterations.csv"), newline="") as f:
            rows = list(csv.DictReader(f))
        self.assertEqual(list(rows[0].keys()), p.CSV_FIELDS)
        self.assertEqual(p.CSV_FIELDS[:8], [
            "device", "soc_model", "mem_total_kb", "config", "iter", "warmup",
            "num_threads", "pin_big_cores"])
        self.assertEqual(p.CSV_FIELDS[-1], "rss_per_step")
        self.assertEqual(len(rows), 4 + 3)
        self.assertEqual(rows[0]["device"], "Pixel 9")
        self.assertEqual(rows[0]["soc_model"], "Tensor G4")
        self.assertEqual(rows[0]["warmup"], "True")
        self.assertEqual(rows[1]["prove_jwt_ms"], "1000")

    def test_stdout_matches_file(self):
        self.assertEqual(self.stdout.strip(), self.md.strip())

    def test_header_and_status(self):
        self.assertIn("Pixel 9", self.md)
        self.assertIn("Tensor G4", self.md)
        self.assertIn("8.0 GiB", self.md)
        self.assertIn("4/8", self.md)
        self.assertIn("Status: complete", self.md)

    def test_warmup_excluded_odd_median(self):
        self.assertIn("| prove_jwt_ms | 2000.0 | 1000.0 | 3000.0 |", self.md)
        self.assertNotIn("9999", self.md)
        self.assertIn("n=3", self.md)

    def test_even_n_median_config_b(self):
        self.assertIn("n=2", self.md)
        self.assertIn("| prove_jwt_ms | 4000.0 | 3000.0 | 5000.0 |", self.md)

    def test_peak_rss_mib(self):
        self.assertIn("prove_jwt 3072.0 MiB", self.md)

    def test_sizes(self):
        self.assertIn("jwt proving key 250.0 MB", self.md)
        self.assertIn("jwt proof 300.0 KB", self.md)

    def test_cross_device_table(self):
        self.assertIn(
            "| Pixel 9 | Tensor G4 | 8.0 | - | - | 2000.0 | 4000.0 | 2.00 | 502.0 | 3072.0 | complete |",
            self.md)


class ProdPathTest(FtlTestCase):
    def test_complete_with_prod(self):
        self.write_logcat("dev", prod_fixture())
        self.run_main(self.root)
        md = self.read("bench_summary.md")
        self.assertLess(md.index("Production path (keys from disk), n=3"), md.index("### Config A"))
        self.assertIn("| prove_jwt_ms | 5000.0 | 4000.0 | 6000.0 |", md)
        self.assertIn("| prove_show_ms | 702.0 | 701.0 | 703.0 |", md)
        self.assertIn("Max peak RSS prove_jwt: 2300.0 MiB", md)
        self.assertIn("Median base RSS prove_jwt: 1000.0 MiB", md)
        self.assertIn("Prove increment: prove_jwt 1300.0 MiB, prove_show 750.0 MiB", md)
        self.assertNotIn("process-wide", md)
        self.assertIn("Status: complete", md)
        self.assertIn(
            "| Pixel 9 | Tensor G4 | 8.0 | 5000.0 | 2300.0 / 1300.0 | 2000.0 | 4000.0 | 2.00 | 502.0 | 3072.0 | complete |",
            md)
        with open(os.path.join(self.root, "bench_prod.csv"), newline="") as f:
            rows = list(csv.DictReader(f))
        self.assertEqual(list(rows[0].keys()), p.PROD_CSV_FIELDS)
        self.assertEqual(p.PROD_CSV_FIELDS[:4], ["device", "soc_model", "mem_total_kb", "iter"])
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[1]["device"], "Pixel 9")
        self.assertEqual(rows[1]["prove_jwt_ms"], "6000")

    def test_killed_during_config_a_after_prod(self):
        lines = [device_line()] + [prod_line(i) for i in (1, 2, 3)] + [
            sizes_line("A"), bench_line("A", 0, warmup=True), bench_line("A", 1),
            "10-26 14:05:01.000   500   500 I lmkd    : Kill 'com.openac.app' (8123), uid 10123, oom_adj 0 to free 1234kB"]
        self.write_logcat("dev", lines)
        self.run_main(self.root)
        md = self.read("bench_summary.md")
        self.assertIn("Production path (keys from disk), n=3", md)
        self.assertIn("5 iterations completed: P=3, A=2, B=0", md)
        self.assertIn("FAILED", md)

    def test_process_wide_label(self):
        self.write_logcat("dev", prod_fixture(rss_per_step=False))
        self.run_main(self.root)
        md = self.read("bench_summary.md")
        self.assertIn("Max peak RSS prove_jwt: 2300.0 MiB (process-wide)", md)
        self.assertIn("Median base RSS prove_jwt: 1000.0 MiB (process-wide)", md)
        self.assertIn("Prove increment: prove_jwt 1300.0 MiB, prove_show 750.0 MiB (process-wide)", md)

    def test_no_prod_lines(self):
        self.write_logcat("dev", complete_fixture())
        self.run_main(self.root)
        self.assertNotIn("Production path", self.read("bench_summary.md"))
        self.assertEqual(len(self.read("bench_prod.csv").splitlines()), 1)


class ThreadsTest(FtlTestCase):
    def run_lines(self, lines):
        self.write_logcat("dev", [device_line(), sizes_line("A")] + lines + [done_line()])
        self.run_main(self.root)
        return self.read("bench_summary.md")

    def test_csv_columns(self):
        self.assertEqual(p.CSV_FIELDS[7:10], ["pin_big_cores", "pool_threads", "pinned_threads"])
        self.run_lines([bench_line("A", 1, pool_threads=4, pinned_threads=4)])
        with open(os.path.join(self.root, "bench_iterations.csv"), newline="") as f:
            row = next(csv.DictReader(f))
        self.assertEqual((row["pool_threads"], row["pinned_threads"]), ("4", "4"))

    def test_threads_line_and_no_warning_when_fully_pinned(self):
        md = self.run_lines([bench_line("A", i, pool_threads=4, pinned_threads=4) for i in (1, 2)])
        self.assertIn("Threads: pool 4, pinned 4", md)
        self.assertNotIn("WARNING", md)
        self.assertNotIn("pin incomplete", md)

    def test_threads_range_when_values_vary(self):
        md = self.run_lines([bench_line("A", 1, pool_threads=4, pinned_threads=4, pin_big_cores=False),
                             bench_line("A", 2, pool_threads=6, pinned_threads=0, pin_big_cores=False)])
        self.assertIn("Threads: pool 4\u20136, pinned 0\u20134", md)
        self.assertNotIn("WARNING", md)

    def test_missing_fields_show_dash_without_warning(self):
        md = self.run_lines([bench_line("A", 1)])
        self.assertIn("Threads: pool -, pinned -", md)
        self.assertNotIn("WARNING", md)

    def test_incomplete_pinning_warns_and_flags_ratio(self):
        lines = [bench_line("A", 1, prove_jwt_ms=1000, pin_big_cores=False, pool_threads=8, pinned_threads=0),
                 sizes_line("B"),
                 bench_line("B", 1, prove_jwt_ms=2000, pool_threads=4, pinned_threads=4),
                 bench_line("B", 2, prove_jwt_ms=2000, pool_threads=4, pinned_threads=3)]
        md = self.run_lines(lines)
        self.assertIn("WARNING: pinning incomplete (pinned 3 of 4 threads)", md)
        self.assertEqual(md.count("WARNING"), 1)
        self.assertIn("| 2.00 (pin incomplete) |", md)


class ProdContractTest(FtlTestCase):
    def md_for(self, lines):
        self.write_logcat("dev", lines)
        self.run_main(self.root)
        return self.read("bench_summary.md")

    def test_wall_rows_are_labelled(self):
        md = self.md_for([device_line(), prod_line(1)])
        self.assertIn("| verify_jwt_wall_ms (incl. key/proof load) | 30.0 | 30.0 | 30.0 |", md)
        self.assertIn("| verify_show_wall_ms (incl. key/proof load) | 40.0 | 40.0 | 40.0 |", md)

    def test_old_format_verify_fields_read_as_wall(self):
        old = prod_line(1)
        old = old.replace("verify_jwt_wall_ms", "verify_jwt_ms").replace("verify_show_wall_ms", "verify_show_ms")
        md = self.md_for([device_line(), old])
        self.assertIn("| verify_jwt_wall_ms (incl. key/proof load) | 30.0 | 30.0 | 30.0 |", md)

    def test_peaks_and_increments_for_four_steps(self):
        md = self.md_for([device_line()] + [prod_line(i) for i in (1, 2, 3)])
        self.assertIn("Max peak RSS other steps: reblind_jwt 600.0 MiB, prove_show 1650.0 MiB, verify_jwt 650.0 MiB", md)
        self.assertIn("Other increments: reblind_jwt 100.0 MiB, verify_jwt 100.0 MiB", md)

    def test_csv_has_new_columns(self):
        self.md_for([device_line(), prod_line(1)])
        self.assertIn("verify_jwt_wall_ms", p.PROD_CSV_FIELDS)
        self.assertIn("base_rss_verify_show_kb", p.PROD_CSV_FIELDS)
        with open(os.path.join(self.root, "bench_prod.csv"), newline="") as f:
            row = next(csv.DictReader(f))
        self.assertEqual(row["verify_jwt_wall_ms"], "30")
        self.assertEqual(row["peak_rss_reblind_show_kb"], str(1024 * 560))

    def test_setup_failure_error_shown_in_prod_section(self):
        err = line("OPENAC_ERROR", {"config": "P", "iter": -1, "error": "key load failed"})
        md = self.md_for([device_line(), err])
        self.assertIn("Production path (keys from disk), n=0", md)
        self.assertIn("setup failed: key load failed", md)


class KillPriorityTest(FtlTestCase):
    FINISHED = ("10-26 14:05:00.000   600   600 I ActivityManager: Killing 8123:com.openac.app/u0a123 "
                "(adj 0): stop com.openac.app due to finished inst")
    LMKD = "10-26 14:05:05.000   500   500 I lmkd    : Kill 'com.openac.app' (8123), uid 10123, oom_adj 0 to free 1234kB"

    def status(self, extra):
        self.write_logcat("dev", [device_line(), sizes_line("A"), bench_line("A", 1)] + extra)
        self.run_main(self.root)
        return next(l for l in self.read("bench_summary.md").splitlines() if l.startswith("Status:"))

    def test_finished_inst_is_not_a_kill(self):
        self.assertIn("FAILED: no OPENAC_DONE", self.status([self.FINISHED]))

    def test_lmkd_after_finished_inst(self):
        status = self.status([self.FINISHED, self.LMKD])
        self.assertIn("lmkd", status)
        self.assertNotIn("finished inst", status)

    def test_lmkd_preferred_over_earlier_activity_manager_killing(self):
        killing = ("10-26 14:05:00.000   600   600 I ActivityManager: Killing 8123:com.openac.app/u0a123 "
                   "(adj 0): crash")
        status = self.status([killing, self.LMKD])
        self.assertIn("lmkd", status)

    def test_activity_manager_killing_used_when_alone(self):
        killing = ("10-26 14:05:00.000   600   600 I ActivityManager: Killing 8123:com.openac.app/u0a123 "
                   "(adj 0): excessive cpu")
        self.assertIn("excessive cpu", self.status([killing]))


class PinnedEndTest(FtlTestCase):
    def run_lines(self, lines):
        self.write_logcat("dev", [device_line(), sizes_line("A")] + lines + [done_line()])
        self.run_main(self.root)
        return self.read("bench_summary.md")

    def test_csv_column_order(self):
        self.assertEqual(p.CSV_FIELDS[7:11],
                         ["pin_big_cores", "pool_threads", "pinned_threads", "pinned_threads_end"])
        self.run_lines([bench_line("A", 1, pool_threads=4, pinned_threads=4, pinned_threads_end=3)])
        with open(os.path.join(self.root, "bench_iterations.csv"), newline="") as f:
            self.assertEqual(next(csv.DictReader(f))["pinned_threads_end"], "3")

    def test_threads_line_shows_end(self):
        md = self.run_lines([bench_line("A", 1, pool_threads=4, pinned_threads=4, pinned_threads_end=4)])
        self.assertIn("Threads: pool 4, pinned 4 (end 4)", md)
        self.assertNotIn("WARNING", md)

    def test_lost_pinning_warns_and_flags_ratio(self):
        lines = [bench_line("A", 1, prove_jwt_ms=1000, pin_big_cores=False),
                 sizes_line("B"),
                 bench_line("B", 1, prove_jwt_ms=2000, pool_threads=4, pinned_threads=4, pinned_threads_end=2)]
        md = self.run_lines(lines)
        self.assertIn("Threads: pool 4, pinned 4 (end 2)", md)
        self.assertIn("WARNING: pinning lost during run (end 2 of 4 threads)", md)
        self.assertNotIn("pinning incomplete", md)
        self.assertIn("| 2.00 (pin incomplete) |", md)

    def test_start_incomplete_does_not_also_report_lost(self):
        md = self.run_lines([bench_line("A", 1, pool_threads=4, pinned_threads=3, pinned_threads_end=3)])
        self.assertIn("WARNING: pinning incomplete (pinned 3 of 4 threads)", md)
        self.assertNotIn("pinning lost", md)

    def test_missing_end_no_warning(self):
        md = self.run_lines([bench_line("A", 1, pool_threads=4, pinned_threads=4)])
        self.assertIn("Threads: pool 4, pinned 4 (end -)", md)
        self.assertNotIn("WARNING", md)

    def test_unpinned_run_with_end_zero_no_warning(self):
        md = self.run_lines([bench_line("A", 1, pin_big_cores=False, pool_threads=4,
                                        pinned_threads=0, pinned_threads_end=0)])
        self.assertNotIn("WARNING", md)


class EvenMedianTest(FtlTestCase):
    def test_even_n(self):
        lines = [device_line(), sizes_line("A")]
        for i, v in enumerate([1000, 2000, 3000, 10000]):
            lines.append(bench_line("A", i, prove_jwt_ms=v))
        lines.append(done_line(ok_a=4, ok_b=0))
        self.write_logcat("dev", lines)
        self.run_main(self.root)
        self.assertIn("| prove_jwt_ms | 2500.0 | 1000.0 | 10000.0 |", self.read("bench_summary.md"))


class KilledDeviceTest(FtlTestCase):
    def test_lmk_mid_config_a(self):
        lines = [device_line(), sizes_line("A"),
                 bench_line("A", 0, warmup=True), bench_line("A", 1),
                 "10-26 14:05:01.000   500   500 I lmkd    : Kill 'com.openac.app' (8123), uid 10123, oom_adj 0 to free 1234kB",
                 "10-26 14:05:02.000   600   600 I ActivityManager: Process com.openac.app (pid 8123) has died"]
        self.write_logcat("akita-35-en-portrait", lines)
        self.run_main(self.root)
        md = self.read("bench_summary.md")
        self.assertIn("FAILED", md)
        self.assertIn("lmkd", md)
        self.assertIn("2 iterations completed", md)
        self.assertNotIn("has died", md)
        self.assertIn("n=1", md)

    def test_no_done_no_kill_line(self):
        self.write_logcat("dev", [device_line(), sizes_line("A"), bench_line("A", 1)])
        self.run_main(self.root)
        md = self.read("bench_summary.md")
        self.assertIn("FAILED: no OPENAC_DONE", md)

    def test_process_died_and_fatal_signal(self):
        self.assertIn("has died", p.find_kill_reason(
            "10-26 14:05:02.000   600   600 I ActivityManager: Process com.openac.app (pid 8123) has died: fg  TOP"))
        self.assertIn("Fatal signal", p.find_kill_reason(
            "10-26 14:05:02.000  8123  8123 F libc    : Fatal signal 11 (SIGSEGV), code 1", {8123}))
        self.assertIsNone(p.find_kill_reason(
            "10-26 14:05:01.000   500   500 I lmkd    : Kill 'com.other.app' (1), uid 1"))


FOREIGN_FATAL = "10-26 14:04:00.000  4242  4242 F libc    : Fatal signal 6 (SIGABRT), code -1 in tid 4242 (other)"
APP_FATAL = "10-26 14:04:30.000  8123  8123 F libc    : Fatal signal 11 (SIGSEGV), code 1 in tid 8123 (openac)"


class FatalSignalScopeTest(FtlTestCase):
    def status_line(self, lines):
        self.write_logcat("dev", lines)
        self.run_main(self.root)
        return next(l for l in self.read("bench_summary.md").splitlines() if l.startswith("Status:"))

    def test_foreign_fatal_in_complete_run(self):
        lines = complete_fixture()
        lines.insert(3, FOREIGN_FATAL)
        self.assertEqual(self.status_line(lines), "Status: complete")

    def test_foreign_fatal_without_done(self):
        lines = [device_line(), sizes_line("A"), FOREIGN_FATAL, bench_line("A", 1)]
        status = self.status_line(lines)
        self.assertIn("FAILED: no OPENAC_DONE", status)
        self.assertNotIn("SIGABRT", status)

    def test_app_pid_fatal_mid_run(self):
        lines = [FOREIGN_FATAL, device_line(), sizes_line("A"), bench_line("A", 1), APP_FATAL]
        status = self.status_line(lines)
        self.assertIn("SIGSEGV", status)
        self.assertNotIn("SIGABRT", status)

    def test_marker_under_foreign_tag_does_not_register_pid(self):
        foreign_marker = "10-26 14:03:50.000  4242  4242 I other   : OPENAC_BENCH " + json.dumps(
            {"config": "A", "iter": 9, "warmup": False})
        lines = [device_line(), sizes_line("A"), foreign_marker, FOREIGN_FATAL]
        status = self.status_line(lines)
        self.assertIn("FAILED: no OPENAC_DONE", status)
        self.assertNotIn("SIGABRT", status)

    def test_fatal_before_first_marker_matches_start_proc_pid(self):
        start = "10-26 14:00:00.000   600   600 I ActivityManager: Start proc 8123:com.openac.app/u0a123 for activity"
        lines = [start, APP_FATAL, device_line(), sizes_line("A")]
        self.assertIn("SIGSEGV", self.status_line(lines))


class MalformedAndNoiseTest(FtlTestCase):
    def test_malformed_ignored_and_counted(self):
        lines = [device_line(), sizes_line("A"),
                 PREFIX + "OPENAC_BENCH {not json",
                 bench_line("A", 1),
                 PREFIX + "OPENAC_BENCHMARK_HELPER started",
                 "10-26 14:03:12.000  8123  8123 W System  : OPENAC mention without marker",
                 "",
                 done_line(ok_a=1, ok_b=0)]
        self.write_logcat("dev", lines)
        self.run_main(self.root)
        md = self.read("bench_summary.md")
        self.assertIn("Malformed marker lines: 1", md)
        with open(os.path.join(self.root, "bench_iterations.csv"), newline="") as f:
            self.assertEqual(len(list(csv.DictReader(f))), 1)

    def test_clean_log_has_no_malformed_note(self):
        self.write_logcat("dev", complete_fixture())
        self.run_main(self.root)
        self.assertNotIn("Malformed", self.read("bench_summary.md"))


class LabelAndInputTest(FtlTestCase):
    def test_label_falls_back_to_dir_name(self):
        lines = [l for l in complete_fixture() if "OPENAC_DEVICE" not in l]
        self.write_logcat("akita-35-en-portrait", lines)
        self.run_main(self.root)
        md = self.read("bench_summary.md")
        self.assertIn("akita-35-en-portrait", md)
        with open(os.path.join(self.root, "bench_iterations.csv"), newline="") as f:
            self.assertEqual(next(csv.DictReader(f))["device"], "akita-35-en-portrait")

    def test_single_file_argument(self):
        path = self.write_logcat("shiba-34-en-portrait", complete_fixture(), name="run.txt")
        out = os.path.join(self.root, "out")
        stdout = self.run_main(path, "--out-dir", out)
        self.assertTrue(os.path.exists(os.path.join(out, "bench_iterations.csv")))
        self.assertIn("Pixel 9", stdout)
        self.assertIn("Pixel 9", self.read("bench_summary.md", out))

    def test_multiple_devices_in_directory(self):
        self.write_logcat("akita-35-en-portrait", complete_fixture())
        other = [device_line(product_model="Galaxy A15", soc_model="Helio G99")] + [
            l for l in complete_fixture() if "OPENAC_DEVICE" not in l][:-1]
        self.write_logcat("a15-34-en-portrait", other)
        stdout = self.run_main(self.root)
        self.assertIn("## Galaxy A15", stdout)
        self.assertIn("## Pixel 9", stdout)
        self.assertIn("FAILED", stdout)
        with open(os.path.join(self.root, "bench_iterations.csv"), newline="") as f:
            self.assertEqual(len(list(csv.DictReader(f))), 14)


class RealFormatTest(FtlTestCase):
    def test_header_crlf_and_binary_bytes(self):
        lines = ["--------- beginning of main"] + complete_fixture()
        path = os.path.join(self.root, "logcat")
        with open(path, "wb") as f:
            f.write("\r\n".join(lines).encode() + b"\r\n")
            f.write(b"10-26 14:09:00.000   1   1 D junk : \xff\xfe\x80 bad bytes\r\n")
        self.run_main(self.root)
        md = self.read("bench_summary.md")
        self.assertIn("Status: complete", md)
        self.assertNotIn("Malformed", md)
        self.assertIn("| prove_jwt_ms | 2000.0 | 1000.0 | 3000.0 |", md)

    def test_non_utf8_inside_marker_line_does_not_crash(self):
        path = os.path.join(self.root, "logcat")
        with open(path, "wb") as f:
            f.write((device_line() + "\n").encode())
            f.write(PREFIX.encode() + b'OPENAC_ERROR {"msg": "bad \xff byte"}\n')
            f.write((done_line(ok_a=0, ok_b=0, errors=1) + "\n").encode())
        self.run_main(self.root)
        self.assertIn("complete (1 errors)", self.read("bench_summary.md"))

    def test_deeply_nested_ftl_layout(self):
        d = os.path.join(self.root, "matrix_1", "akita-35-en-portrait", "test_cases", "x")
        os.makedirs(d)
        lines = [l for l in complete_fixture() if "OPENAC_DEVICE" not in l]
        with open(os.path.join(d, "logcat"), "w") as f:
            f.write("\n".join(lines))
        self.run_main(self.root)
        # fallback label is the first path component under the results dir
        self.assertIn("## matrix_1", self.read("bench_summary.md"))

    def test_empty_dir_returns_1(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = p.main([self.root])
        self.assertEqual(rc, 1)
        self.assertIn("no logcat files found", err.getvalue())

    def test_out_dir_created_recursively(self):
        self.write_logcat("dev", complete_fixture())
        out = os.path.join(self.root, "a", "b", "c")
        self.run_main(self.root, "--out-dir", out)
        for name in ("bench_iterations.csv", "bench_prod.csv", "bench_summary.md"):
            self.assertTrue(os.path.exists(os.path.join(out, name)))

    def test_single_logcat_file_label_is_parent_dir(self):
        lines = [l for l in complete_fixture() if "OPENAC_DEVICE" not in l]
        path = self.write_logcat("shiba-34-en-portrait", lines)
        out = os.path.join(self.root, "out")
        self.run_main(path, "--out-dir", out)
        self.assertIn("## artifacts", self.read("bench_summary.md", out))


class MarkerParsingTest(FtlTestCase):
    def test_marker_from_other_tag_is_accepted(self):
        other = "10-26 14:03:11.600  9999  9999 I SomeOtherTag : OPENAC_DEVICE " + json.dumps(DEVICE)
        res = p.parse_logcat(other)
        self.assertEqual(res["device"]["product_model"], "Pixel 9")

    def test_marker_string_inside_json_field(self):
        row = line("OPENAC_BENCH", {"config": "A", "iter": 1, "warmup": False,
                                    "note": "see OPENAC_DONE {\"errors\": 5} here", "prove_jwt_ms": 7})
        res = p.parse_logcat(row)
        self.assertEqual(len(res["bench"]), 1)
        self.assertIsNone(res["done"])
        self.assertEqual(res["malformed"], 0)

    def test_marker_line_without_json_is_malformed(self):
        res = p.parse_logcat(PREFIX + "OPENAC_DONE ")
        self.assertEqual(res["malformed"], 1)
        self.assertIsNone(res["done"])

    def test_non_object_json_is_malformed_not_a_crash(self):
        for marker in ("SIZES", "BENCH", "PROD", "DONE", "DEVICE"):
            with self.subTest(marker=marker):
                text = "\n".join([PREFIX + f"OPENAC_{marker} 5", PREFIX + f"OPENAC_{marker} null",
                                  PREFIX + f"OPENAC_{marker} [1]"])
                res = p.parse_logcat(text)
                self.assertEqual(res["malformed"], 3)
                p.summary_md([{**res, "label": "x"}])

    def test_last_device_wins(self):
        text = "\n".join([device_line(product_model="First"), device_line(product_model="Second")])
        self.assertEqual(p.parse_logcat(text)["device"]["product_model"], "Second")

    def test_error_markers_collected(self):
        res = p.parse_logcat(line("OPENAC_ERROR", {"config": "A", "msg": "boom"}))
        self.assertEqual(res["errors"], [{"config": "A", "msg": "boom"}])


class StatusTest(FtlTestCase):
    def status(self, lines):
        self.write_logcat("dev", lines)
        self.run_main(self.root)
        return next(l for l in self.read("bench_summary.md").splitlines() if l.startswith("Status:"))

    def test_done_with_errors(self):
        lines = [device_line(), sizes_line("A"), bench_line("A", 1), done_line(errors=2)]
        self.assertEqual(self.status(lines), "Status: complete (2 errors)")

    def test_long_status_truncated_in_cross_table(self):
        kill = "10-26 14:05:01.000   500   500 I lmkd    : Kill 'com.openac.app' (8123) | " + "x" * 200
        self.write_logcat("dev", [device_line(), bench_line("A", 1), kill])
        self.run_main(self.root)
        row = next(l for l in self.read("bench_summary.md").splitlines() if l.startswith("| Pixel 9"))
        status = row.rstrip(" |").split(" | ")[-1]
        self.assertTrue(status.endswith("..."))
        self.assertLessEqual(len(status), 80)

    def test_pipe_in_short_status_is_escaped(self):
        kill = "10-26 14:05:01.000   500   500 I lmkd    : Kill 'com.openac.app' | x"
        self.write_logcat("dev", [device_line(), kill])
        self.run_main(self.root)
        row = next(l for l in self.read("bench_summary.md").splitlines() if l.startswith("| Pixel 9"))
        self.assertIn("\\|", row)

    def test_status_counts_ignore_unknown_config(self):
        status = self.status([device_line(), bench_line("C", 1), bench_line("A", 1)])
        self.assertIn("2 iterations completed: P=0, A=1, B=0", status)


class EdgeStatsTest(FtlTestCase):
    def summary(self, lines):
        self.write_logcat("dev", lines)
        self.run_main(self.root)
        return self.read("bench_summary.md")

    def test_median_n1(self):
        md = self.summary([device_line(), bench_line("A", 1, prove_jwt_ms=1234), done_line()])
        self.assertIn("### Config A (n=1)", md)
        self.assertIn("| prove_jwt_ms | 1234.0 | 1234.0 | 1234.0 |", md)

    def test_zero_measured_iterations_for_config(self):
        md = self.summary([device_line(), bench_line("A", 0, warmup=True),
                           bench_line("B", 1, prove_jwt_ms=4000), done_line()])
        self.assertNotIn("### Config A", md)
        self.assertIn("### Config B (n=1)", md)
        row = next(l for l in md.splitlines() if l.startswith("| Pixel 9"))
        self.assertIn("| - | 4000.0 | - | - |", row)

    def test_no_bench_at_all(self):
        md = self.summary([device_line(), done_line(ok_a=0, ok_b=0)])
        self.assertNotIn("### Config", md)
        row = next(l for l in md.splitlines() if l.startswith("| Pixel 9"))
        self.assertIn("| - | - | - | - | - | - | - | complete |", row)

    def test_bench_missing_optional_fields(self):
        row = {"config": "A", "iter": 1, "warmup": False, "prove_jwt_ms": 500}
        md = self.summary([device_line(), line("OPENAC_BENCH", row), done_line()])
        self.assertIn("| prove_jwt_ms | 500.0 | 500.0 | 500.0 |", md)
        self.assertNotIn("| reblind_jwt_ms |", md)
        self.assertIn("Max peak RSS: prove_jwt - MiB, prove_show - MiB, jwt_setup - MiB", md)
        with open(os.path.join(self.root, "bench_iterations.csv"), newline="") as f:
            r = next(csv.DictReader(f))
        self.assertEqual(r["prove_jwt_ms"], "500")
        self.assertEqual(r["reblind_jwt_ms"], "")
        self.assertEqual(r["num_threads"], "")
        self.assertEqual(r["rss_per_step"], "")

    def test_bench_null_timing_is_skipped(self):
        md = self.summary([device_line(), bench_line("A", 1, prove_jwt_ms=None),
                           bench_line("A", 2, prove_jwt_ms=900)])
        self.assertIn("| prove_jwt_ms | 900.0 | 900.0 | 900.0 |", md)

    def test_device_without_memory_or_cores(self):
        md = self.summary([line("OPENAC_DEVICE", {"product_model": "Bare"}), done_line()])
        self.assertIn("RAM: - GiB", md)
        self.assertIn("big cores: 0/0", md)

    def test_prod_rss_per_step_mixed_is_process_wide(self):
        md = self.summary([device_line(), prod_line(1, rss_per_step=True),
                           prod_line(2, rss_per_step=False), prod_line(3, rss_per_step=True),
                           done_line()])
        self.assertIn("(process-wide)", md)

    def test_prod_missing_rss_fields(self):
        md = self.summary([device_line(), line("OPENAC_PROD", {"iter": 1, "prove_jwt_ms": 10}),
                           done_line()])
        self.assertIn("(process-wide)", md)
        self.assertIn("Max peak RSS prove_jwt: - MiB", md)
        self.assertIn("Prove increment: prove_jwt - MiB, prove_show - MiB", md)


class LabelCollisionTest(FtlTestCase):
    def test_same_product_model_gets_disambiguated(self):
        self.write_logcat("akita-35-en-portrait", complete_fixture())
        self.write_logcat("akita-34-en-portrait", complete_fixture())
        self.run_main(self.root)
        md = self.read("bench_summary.md")
        labels = [l[3:] for l in md.splitlines() if l.startswith("## ") and l != "## All devices"]
        self.assertEqual(len(set(labels)), 2)
        self.assertTrue(all(l.startswith("Pixel 9") for l in labels))
        with open(os.path.join(self.root, "bench_iterations.csv"), newline="") as f:
            devices = {r["device"] for r in csv.DictReader(f)}
        self.assertEqual(len(devices), 2)

    def test_three_way_collision_stays_unique(self):
        for d in ("a-1", "b-2", "c-3"):
            self.write_logcat(d, complete_fixture())
        self.run_main(self.root)
        labels = [l[3:] for l in self.read("bench_summary.md").splitlines()
                  if l.startswith("## ") and l != "## All devices"]
        self.assertEqual(len(set(labels)), 3)


if __name__ == "__main__":
    unittest.main()
