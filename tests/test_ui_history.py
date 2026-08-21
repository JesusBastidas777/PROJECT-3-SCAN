import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from scanner.ui.screens.history import render


class UIHistoryTests(unittest.TestCase):
    def test_rows_are_bounded(self):
        self.assertEqual(render({"scans": [{"scan_id": str(i)} for i in range(50)]}, max_rows=4).row_count, 4)
