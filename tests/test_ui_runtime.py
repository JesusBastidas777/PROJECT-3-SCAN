import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from scanner.ui.screens.runtime import render


class UIRuntimeTests(unittest.TestCase):
    def test_runtime_components(self):
        self.assertEqual(render({"readiness": {}, "heartbeat": {}, "status": {}, "outbox": {}}).row_count, 4)
