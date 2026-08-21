import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from scanner.ui.screens.findings import render


class UIFindingsTests(unittest.TestCase):
    def test_only_supplied_factual_findings(self):
        view = render({"findings": [{"statement": "TCP connection succeeded.", "confidence": "high", "evidence_refs": ["o"]}]})
        self.assertEqual(view.row_count, 1)
