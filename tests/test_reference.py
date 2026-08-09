from __future__ import annotations

from pathlib import Path
import sys
import unittest


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import gen_reference  # noqa: E402


class ReferenceTests(unittest.TestCase):
    def test_github_heading_anchors_strip_punctuation(self):
        cases = {
            "Database & metadata": "database--metadata",
            "Data & segments (read)": "data--segments-read",
            "Imports / exports / entry points": "imports--exports--entry-points",
        }
        for title, anchor in cases.items():
            with self.subTest(title=title):
                self.assertEqual(anchor, gen_reference.github_anchor(title))


if __name__ == "__main__":
    unittest.main()
