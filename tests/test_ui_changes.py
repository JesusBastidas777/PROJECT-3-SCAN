import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from scanner.ui.screens.changes import render


class UIChangesTests(unittest.TestCase):
    def test_indeterminate_is_separate(self):
        self.assertEqual(render({"comparison": {"changes": [], "indeterminate": [{}]}}).row_count, 5)
