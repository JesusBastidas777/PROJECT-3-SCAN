import sys, unittest
from pathlib import Path
from unittest.mock import Mock, patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from scanner.ui.app import SCANApplication
from scanner.models import SCANResponseV1


class GUIE2ETests(unittest.TestCase):
    def test_unavailable_then_idle_refresh_has_no_acquisition(self):
        service = Mock(); workflow = Mock(); app = SCANApplication(service, workflow=workflow)
        service.check.return_value = SCANResponseV1(status="degraded", data={"ready": False})
        self.assertTrue(app.refresh().stale)
        service.check.return_value = SCANResponseV1(data={"ready": True})
        service.status.return_value = SCANResponseV1(data={"state": "idle"})
        workflow.view.return_value = SCANResponseV1(data={"overview": {}})
        with patch("scanner.scan_pipeline.execute_scan") as scan:
            state = app.refresh(); scan.assert_not_called()
        self.assertEqual(state.status, "idle")
