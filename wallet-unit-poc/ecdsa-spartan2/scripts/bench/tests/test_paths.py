import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import stagelib as sl


def env(**kw):
    return mock.patch.dict(os.environ, {k: v for k, v in kw.items() if v is not None}, clear=True)


class BenchRoot(unittest.TestCase):
    def test_unset_fails_naming_the_variable(self):
        with env(), self.assertRaises(SystemExit) as cm:
            sl.bench_root()
        self.assertIn("OPENACPLUS_BENCH_ROOT", str(cm.exception))

    def test_empty_fails(self):
        with env(OPENACPLUS_BENCH_ROOT=""), self.assertRaises(SystemExit):
            sl.bench_root()

    def test_plain_directory_is_accepted_and_derives_paths(self):
        with tempfile.TemporaryDirectory() as d, env(OPENACPLUS_BENCH_ROOT=d):
            self.assertEqual(sl.bench_root(), d)
            self.assertEqual(sl.laptop_root(), os.path.join(d, "laptop"))
            self.assertEqual(sl.stage_root(), os.path.join(d, "laptop", "stage"))

    def test_inside_git_work_tree_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["git", "init", "-q", d], check=True)
            for root in (d, os.path.join(d, "not", "yet", "created")):
                with env(OPENACPLUS_BENCH_ROOT=root), self.assertRaises(SystemExit) as cm:
                    sl.bench_root()
                self.assertIn("git work tree", str(cm.exception))


class Worktrees(unittest.TestCase):
    def test_unset_fails_naming_the_variable(self):
        with env(), self.assertRaises(SystemExit) as cm:
            sl.worktrees()
        self.assertIn("OPENACPLUS_WORKTREES", str(cm.exception))

    def test_worktree_is_named_after_the_config(self):
        with env(OPENACPLUS_WORKTREES="/w"):
            self.assertEqual(sl.worktree("combined"), "/w/combined")
            self.assertEqual(sl.worktree("headline"), "/w/headline")

    def test_variant_stage_config_uses_the_combined_worktree(self):
        with env(OPENACPLUS_WORKTREES="/w"):
            self.assertEqual(sl.worktree("variant"), "/w/combined")

    def test_binary_path_is_the_release_build(self):
        with env(OPENACPLUS_WORKTREES="/w"):
            self.assertEqual(sl.worktree_binary("v1"), "/w/v1/wallet-unit-poc/ecdsa-spartan2/target/release/openac_bench")


class Refs(unittest.TestCase):
    def test_every_config_pins_shas_and_r1cs_hashes(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "refs.json")) as f:
            refs = json.load(f)
        self.assertEqual(set(refs["configs"]), {"v1", "main", "issuer", "revocation", "combined", "headline"})
        for name, c in refs["configs"].items():
            for k in ("base_sha", "bench_sha", "circuit_commit"):
                self.assertRegex(c[k], r"^[0-9a-f]{40}$", f"{name}.{k}")
            self.assertTrue(c["r1cs"], name)
            for r in c["r1cs"]:
                self.assertRegex(r["r1cs_sha256"], r"^[0-9a-f]{64}$", f"{name}.{r['circuit']}")


if __name__ == "__main__":
    unittest.main()
