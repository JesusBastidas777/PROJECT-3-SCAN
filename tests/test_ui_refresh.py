import sys
from pathlib import Path
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scanner.ui.app import SCANApplication
from scanner.ui.state import UIState


class UIRefreshTests(unittest.TestCase):
    def test_failure_preserves_last_valid_state_as_stale(self):
        service = Mock(); service.check.side_effect = RuntimeError("runtime unavailable")
        app = SCANApplication(service, workflow=Mock())
        previous = UIState(payload={"scan_id": "scan-good"}, status="idle", updated_at="fixed")
        state = app.refresh(previous)
        self.assertTrue(state.stale); self.assertEqual(state.payload, previous.payload)
        self.assertEqual(state.status, "degraded")

    def test_refresh_does_not_import_or_execute_pipeline(self):
        service = Mock(); service.check.return_value.data = {"ready": True}
        workflow = Mock(); workflow.operational_summary.return_value.data = {"status": {"state": "idle"}, "latest_scan": None}
        with patch("scanner.scan_pipeline.execute_scan") as acquisition:
            state = SCANApplication(service, workflow=workflow).refresh()
            acquisition.assert_not_called()
        self.assertEqual(state.status, "idle")
