import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from scanner.ui.screens.coverage import render


class UICoverageTests(unittest.TestCase):
    def test_all_counts_are_columns(self):
        self.assertGreater(len(render({"coverage": {"phases": {}}}).columns), 10)
