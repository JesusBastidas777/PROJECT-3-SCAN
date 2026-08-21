import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scanner.operational_view import build_operational_view, validate_operational_view
from test_service import sample_report


class OperationalViewTests(unittest.TestCase):
    def test_bounded_factual_projection(self):
        report = sample_report(); report.update(schema_version="2.2", partial=False, baseline_eligible=True, acquisition={})
        view = build_operational_view(report, runtime_status={"lifecycle": "idle", "job_state": "completed"})
        validate_operational_view(view)
        self.assertEqual(view["counts"]["open"], 1)
        self.assertEqual(view["counts"]["findings"], 1)
        self.assertNotIn("risk", view)

    def test_partial_never_baseline_eligible(self):
        report = sample_report(); report.update(schema_version="2.2", partial=True, baseline_eligible=False, acquisition={})
        self.assertFalse(build_operational_view(report)["baseline_eligible"])
