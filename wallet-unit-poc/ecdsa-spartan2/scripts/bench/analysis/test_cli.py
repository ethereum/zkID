import csv
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

import synth
from tables import TABLES

HERE = os.path.dirname(os.path.abspath(__file__))


def read(path):
    with open(path, "rb") as f:
        return f.read()


def run(root, out):
    return subprocess.run([sys.executable, os.path.join(HERE, "analyze.py"), "--root", root, "--out", out],
                          capture_output=True, text=True)


class CliTest(unittest.TestCase):
    def test_end_to_end_on_synthetic_rows(self):
        with tempfile.TemporaryDirectory() as d:
            root, out = os.path.join(d, "bench"), os.path.join(d, "out")
            synth.write_root(root)
            r = run(root, out)
            self.assertEqual(r.returncode, 0, r.stderr)
            names = set(os.listdir(out))
            for t in TABLES:
                self.assertIn(t + ".tex", names)
            for f in ("F1", "F2", "F3", "F4", "F5", "F6"):
                self.assertIn(f + ".pdf", names)
                self.assertIn(f + ".csv", names)
            for want in ("checks.md", "fits.md", "provenance.csv"):
                self.assertIn(want, names)
            with open(os.path.join(out, "provenance.csv")) as f:
                tags = {row["table_cell"].split("/")[0] for row in csv.DictReader(f)}
            for t in list(TABLES) + ["F1", "F2", "F3", "F4", "F5", "F6"]:
                self.assertIn(t, tags)
            with open(os.path.join(out, "checks.md")) as f:
                self.assertIn("| iqr |", f.read())

    def test_emitted_tex_is_ascii(self):
        with tempfile.TemporaryDirectory() as d:
            root, out = os.path.join(d, "bench"), os.path.join(d, "out")
            synth.write_root(root)
            self.assertEqual(run(root, out).returncode, 0)
            tex = [f for f in os.listdir(out) if f.endswith(".tex")]
            self.assertTrue(any(f.startswith("F") for f in tex) and any(f.startswith("T") for f in tex))
            for f in tex:
                self.assertTrue(read(os.path.join(out, f)).isascii(), f)

    def test_root_defaults_to_the_env_var_and_is_otherwise_required(self):
        with tempfile.TemporaryDirectory() as d:
            root, out = os.path.join(d, "bench"), os.path.join(d, "out")
            synth.write_root(root)
            cmd = [sys.executable, os.path.join(HERE, "analyze.py"), "--out", out]
            env = {k: v for k, v in os.environ.items() if k != "OPENACPLUS_BENCH_ROOT"}
            r = subprocess.run(cmd, capture_output=True, text=True, env=env)
            self.assertEqual(r.returncode, 2)
            self.assertIn("OPENACPLUS_BENCH_ROOT", r.stderr)
            r = subprocess.run(cmd, capture_output=True, text=True, env=dict(env, OPENACPLUS_BENCH_ROOT=root))
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("F1.tex", os.listdir(out))

    def test_excluded_vk_rows_are_reported_in_checks_md(self):
        with tempfile.TemporaryDirectory() as d:
            root, out = os.path.join(d, "bench"), os.path.join(d, "out")
            rows = synth.mac_run("main")
            for r in rows:
                r.pop("vk_loaded", None)
            synth.write_jsonl(os.path.join(root, "laptop", "runs", "r1", "bench.jsonl"), rows)
            run(root, out)
            self.assertIn("EXCLUDED vk_load", read(os.path.join(out, "checks.md")).decode())

    def test_labels_and_notes_are_written(self):
        with tempfile.TemporaryDirectory() as d:
            root, out = os.path.join(d, "bench"), os.path.join(d, "out")
            synth.write_root(root)
            run(root, out)
            names = set(os.listdir(out))
            for want in ("labels.md", "T1.note.txt", "F6.note.txt"):
                self.assertIn(want, names)

    def test_final_mode_fails_on_missing_data(self):
        with tempfile.TemporaryDirectory() as d:
            root, out = os.path.join(d, "bench"), os.path.join(d, "out")
            synth.write_root(root)
            r = subprocess.run([sys.executable, os.path.join(HERE, "analyze.py"), "--root", root, "--out", out, "--final",
                                "--matrices", os.path.join(d, "none")], capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            md = read(os.path.join(out, "checks.md")).decode()
            self.assertIn("no matrix files found", md)
            self.assertIn("no PHONECHECK row", md)
            self.assertTrue(os.path.exists(os.path.join(out, "provenance.csv")))

    def test_final_passes_on_a_complete_dataset(self):
        with tempfile.TemporaryDirectory() as d:
            root, out, mats = os.path.join(d, "bench"), os.path.join(d, "out"), os.path.join(d, "m")
            synth.write_root(root)
            synth.write_final_extras(root, mats)
            r = subprocess.run([sys.executable, os.path.join(HERE, "analyze.py"), "--root", root, "--out", out, "--final",
                                "--matrices", mats], capture_output=True, text=True)
            md = read(os.path.join(out, "checks.md")).decode()
            self.assertEqual(r.returncode, 0, "\n".join(l for l in md.splitlines() if "| fail |" in l))
            self.assertNotIn("| fail |", md)

    def test_final_fails_when_a_phone_session_is_missing(self):
        with tempfile.TemporaryDirectory() as d:
            root, out, mats = os.path.join(d, "bench"), os.path.join(d, "out"), os.path.join(d, "m")
            synth.write_root(root)
            synth.write_final_extras(root, mats)
            shutil.rmtree(os.path.join(root, "mobile", "s26plus", "combined", "s3"))
            r = subprocess.run([sys.executable, os.path.join(HERE, "analyze.py"), "--root", root, "--out", out, "--final",
                                "--matrices", mats], capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            self.assertIn("2 of 3 sessions", read(os.path.join(out, "checks.md")).decode())

    def test_final_fails_on_a_missing_gc_flag(self):
        with tempfile.TemporaryDirectory() as d:
            root, out, mats = os.path.join(d, "bench"), os.path.join(d, "out"), os.path.join(d, "m")
            synth.write_root(root)
            synth.write_final_extras(root, mats)
            path = os.path.join(root, "registry", "registry.jsonl")
            rows = [dict(r, gc_exposed=False) for r in synth.registry_rows()]
            synth.write_jsonl(path, rows)
            r = subprocess.run([sys.executable, os.path.join(HERE, "analyze.py"), "--root", root, "--out", out, "--final",
                                "--matrices", mats], capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            self.assertIn("| gc |", read(os.path.join(out, "checks.md")).decode())

    def test_fits_md_reports_both_cost_fits(self):
        with tempfile.TemporaryDirectory() as d:
            root, out = os.path.join(d, "bench"), os.path.join(d, "out")
            synth.write_root(root)
            run(root, out)
            md = read(os.path.join(out, "fits.md")).decode()
            self.assertIn("without the linear T term", md)
            self.assertIn("| g |", md)

    def test_rerun_is_identical(self):
        with tempfile.TemporaryDirectory() as d:
            root = os.path.join(d, "bench")
            synth.write_root(root)
            a, b = os.path.join(d, "a"), os.path.join(d, "b")
            run(root, a)
            time.sleep(1.1)
            run(root, b)
            files = sorted(os.listdir(a))
            self.assertEqual(files, sorted(os.listdir(b)))
            self.assertIn("F1.pdf", files)
            for n in files:
                self.assertEqual(read(os.path.join(a, n)), read(os.path.join(b, n)), n)

    def test_output_does_not_depend_on_where_the_root_lives(self):
        with tempfile.TemporaryDirectory() as d:
            r1, r2 = os.path.join(d, "x", "bench"), os.path.join(d, "y", "z", "bench")
            synth.write_root(r1)
            shutil.copytree(r1, r2)
            a, b = os.path.join(d, "a"), os.path.join(d, "b")
            run(r1, a)
            run(r2, b)
            self.assertEqual(read(os.path.join(a, "provenance.csv")), read(os.path.join(b, "provenance.csv")))
            self.assertNotIn(d.encode(), read(os.path.join(a, "provenance.csv")))

    def test_real_shaped_sp_rows_do_not_stop_the_outputs(self):
        with tempfile.TemporaryDirectory() as d:
            root, out = os.path.join(d, "bench"), os.path.join(d, "out")
            rows = []
            for i, pop in enumerate(synth.POPULATIONS):
                r = synth.mac_run("combined", d_iss=8, d_rev=20, matrix_id="S-P", cell=f"sp{i}",
                                  population={"issuers": 256, "revoked": pop})
                del r[0]["rev_path_len"]
                rows += r
            synth.write_jsonl(os.path.join(root, "laptop", "runs", "r1", "bench.jsonl"), rows)
            self.assertEqual(run(root, out).returncode, 0)
            for n in ("checks.md", "fits.md", "provenance.csv", "T1.tex"):
                self.assertTrue(os.path.exists(os.path.join(out, n)), n)
            self.assertIn("rev_path_len", read(os.path.join(out, "checks.md")).decode())
            self.assertIn("SKIP F6: no rows", read(os.path.join(out, "checks.md")).decode())

    def test_smoke_e2e_rows_need_the_flag(self):
        with tempfile.TemporaryDirectory() as d:
            root = os.path.join(d, "bench")
            rows = [dict(r, smoke=True, total_us=777_000_000) for r in synth.e2e_rows() if r["workload"] == "warm"]
            synth.write_jsonl(os.path.join(root, "laptop", "runs", "r1", "e2e.jsonl"), rows)
            a, b = os.path.join(d, "a"), os.path.join(d, "b")
            run(root, a)
            subprocess.run([sys.executable, os.path.join(HERE, "analyze.py"), "--root", root, "--out", b,
                            "--include-smoke"], check=True, capture_output=True)
            self.assertNotIn(b"777", read(os.path.join(a, "T6.tex")))
            self.assertIn(b"777", read(os.path.join(b, "T6.tex")))

    def test_empty_root_still_succeeds(self):
        with tempfile.TemporaryDirectory() as d:
            r = run(d, os.path.join(d, "out"))
            self.assertEqual(r.returncode, 0, r.stderr)
            md = read(os.path.join(d, "out", "checks.md")).decode()
            for name in ("F6", "T5", "T1"):
                self.assertIn(f"SKIP {name}: no rows", md)
            self.assertTrue(os.path.exists(os.path.join(d, "out", "T1.tex")))


if __name__ == "__main__":
    unittest.main()
