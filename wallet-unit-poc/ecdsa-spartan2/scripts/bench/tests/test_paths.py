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


class Creation(unittest.TestCase):
    def test_fresh_root_gets_laptop_and_stage_dirs(self):
        with tempfile.TemporaryDirectory() as d:
            root = os.path.join(d, "fresh", "root")
            with env(OPENACPLUS_BENCH_ROOT=root):
                self.assertEqual(sl.laptop_root(), os.path.join(root, "laptop"))
                self.assertTrue(os.path.isdir(os.path.join(root, "laptop")))
                self.assertTrue(os.path.isdir(sl.stage_root()))

    def test_refused_root_creates_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["git", "init", "-q", d], check=True)
            root = os.path.join(d, "bench")
            with env(OPENACPLUS_BENCH_ROOT=root):
                for fn in (sl.laptop_root, sl.stage_root):
                    with self.assertRaises(SystemExit):
                        fn()
            self.assertFalse(os.path.exists(root))


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

    def test_require_worktree_names_the_expected_path(self):
        with tempfile.TemporaryDirectory() as d, env(OPENACPLUS_WORKTREES=d):
            os.mkdir(os.path.join(d, "main"))
            self.assertEqual(sl.require_worktree("main"), os.path.join(d, "main"))
            with self.assertRaises(SystemExit) as cm:
                sl.require_worktree("issuer")
            self.assertIn(os.path.join(d, "issuer"), str(cm.exception))

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
            self.assertRegex(c["spartan2_rev"], r"^[0-9a-f]{7}$", f"{name}.spartan2_rev")
            for r in c["r1cs"]:
                self.assertRegex(r["r1cs_sha256"], r"^[0-9a-f]{64}$", f"{name}.{r['circuit']}")


class Only(unittest.TestCase):
    def setUp(self):
        import stage_all
        self.sa = stage_all
        self.calls = []
        self.tmp = tempfile.TemporaryDirectory()
        for cfg in ("v1", "main", "issuer", "revocation", "combined"):
            os.mkdir(os.path.join(self.tmp.name, cfg))
        patches = [mock.patch.dict(os.environ, {"OPENACPLUS_WORKTREES": self.tmp.name}),
                   mock.patch.object(stage_all, "run", lambda args: self.calls.append(args[args.index("--cell") + 1]))]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(self.tmp.cleanup)

    def test_no_filter_stages_every_chain_cell(self):
        self.sa.stage_chain(None)
        self.assertEqual(len(self.calls), len(list(self.sa.chain_cells_all())))

    def test_only_selects_exactly_the_named_cells(self):
        self.sa.stage_chain({"A1-main-1k", "X2-v1-1t"})
        self.assertEqual(sorted(self.calls), ["A1-main-1k", "X2-v1-1t"])

    def test_missing_worktree_of_a_selected_cell_names_the_path(self):
        os.rmdir(os.path.join(self.tmp.name, "issuer"))
        with self.assertRaises(SystemExit) as cm:
            self.sa.stage_chain({"A1-issuer-1k"})
        self.assertIn(os.path.join(self.tmp.name, "issuer"), str(cm.exception))

    def test_unselected_cells_do_not_need_their_worktree(self):
        os.rmdir(os.path.join(self.tmp.name, "issuer"))
        self.sa.stage_chain({"A1-main-1k"})
        self.assertEqual(self.calls, ["A1-main-1k"])

    def test_headline_cell_filter(self):
        os.mkdir(os.path.join(self.tmp.name, "headline"))
        self.sa.headline("A1-headline-1k", "A1", "1k", "j", "s", "r", only={"other"})
        self.assertEqual(self.calls, [])
        self.sa.headline("A1-headline-1k", "A1", "1k", "j", "s", "r", only={"A1-headline-1k"})
        self.assertEqual(self.calls, ["A1-headline-1k"])

    def test_generic_parser_takes_only_flag_and_legacy_positionals(self):
        import stage_generic_all as sg
        self.assertEqual(sg.parse_only(["--only", "S-N-sn_show_n2", "W-w2"]), {"S-N-sn_show_n2", "W-w2"})
        self.assertEqual(sg.parse_only(["W-w2", "--patch-meta"]), {"W-w2"})
        self.assertEqual(sg.parse_only([]), set())


LOCK = """\
[[package]]
name = "spartan2"
version = "0.4.0"
source = "git+https://github.com/0xVikasRushi/Spartan2.git?branch=openac-sdk#64687aff151924331cb573f66954c75d1eb20ee5"

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""


class Spartan2Rev(unittest.TestCase):
    def worktree_with(self, d, lock):
        eco = os.path.join(d, "wallet-unit-poc", "ecdsa-spartan2")
        os.makedirs(eco)
        if lock is not None:
            with open(os.path.join(eco, "Cargo.lock"), "w") as f:
                f.write(lock)
        return d

    def test_reads_the_short_git_rev_of_the_spartan2_package(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(sl.spartan2_rev(self.worktree_with(d, LOCK)), "64687af")

    def test_missing_lock_fails_clearly(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(SystemExit) as cm:
            sl.spartan2_rev(self.worktree_with(d, None))
        self.assertIn("Cargo.lock", str(cm.exception))

    def test_lock_without_a_spartan2_git_source_fails_clearly(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(SystemExit) as cm:
            sl.spartan2_rev(self.worktree_with(d, '[[package]]\nname = "serde"\nversion = "1.0.0"\n'))
        self.assertIn("spartan2", str(cm.exception))


class DigestSidecar(unittest.TestCase):
    def test_sidecar_is_copied_next_to_the_staged_key(self):
        import stage
        with tempfile.TemporaryDirectory() as d:
            src, dst = os.path.join(d, "2k_show_verifying.key"), os.path.join(d, "out", "show_verifying.key")
            os.makedirs(os.path.dirname(dst))
            with open(os.path.join(d, "2k_show_verifying.digest"), "wb") as f:
                f.write(b"x" * 32)
            stage.stage_digest(src, dst)
            with open(os.path.join(d, "out", "show_verifying.digest"), "rb") as f:
                self.assertEqual(f.read(), b"x" * 32)

    def test_absent_sidecar_is_skipped_silently(self):
        import stage
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "out"))
            stage.stage_digest(os.path.join(d, "2k_show_verifying.key"), os.path.join(d, "out", "show_verifying.key"))
            self.assertEqual(os.listdir(os.path.join(d, "out")), [])


if __name__ == "__main__":
    unittest.main()
