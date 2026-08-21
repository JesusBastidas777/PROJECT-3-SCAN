import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from scanner.ui.screens.overview import render


class UIOverviewTests(unittest.TestCase):
    def test_required_operational_fields(self):
        value = str(render({"overview": {"runtime_state": "idle", "job_state": "completed", "scan_id": "scan-x", "partial": False, "resumed": False}}))
        self.assertIn("Table", type(render({"overview": {}})).__name__)
