import os
import tempfile
import unittest

from figures import FIGURES
from labels import LABELS, REQUIRED, write_labels
from tables import TABLES


class LabelsTest(unittest.TestCase):
    def test_every_output_has_labels_and_every_label_exists(self):
        for name in list(TABLES) + list(FIGURES):
            self.assertTrue(REQUIRED.get(name), name)
            for lid in REQUIRED[name]:
                self.assertIn(lid, LABELS)

    def test_the_plan_and_review_labels_are_present(self):
        text = " ".join(LABELS.values())
        for want in ("no role tags", "not bound to the issuer", "2n+6", "2M attribute names", "no `prepareBatch`",
                     "as large as the PK", "predate the security", "OpenAC as published", "page-cache warm",
                     "VK digest", "default fixture registries", "upper bound"):
            self.assertIn(want, text)

    def test_files_carry_every_required_label_per_output(self):
        with tempfile.TemporaryDirectory() as d:
            write_labels(d)
            with open(os.path.join(d, "labels.md")) as f:
                md = f.read()
            for name in list(TABLES) + list(FIGURES):
                with open(os.path.join(d, f"{name}.note.txt")) as f:
                    note = f.read()
                for lid in REQUIRED[name]:
                    self.assertIn(LABELS[lid], note, f"{name} {lid}")
                self.assertIn(f"## {name}", md)


if __name__ == "__main__":
    unittest.main()
