import sys
import threading
from pathlib import Path
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scanner import SCANConfig, SCANService
from scanner.runtime import SCANRuntime
from scanner.runtime_paths import SCANRuntimeConfig
from test_service_execution import request


class ServiceCancelTests(unittest.TestCase):
    def test_cooperative_cancel_preserves_partial_report(self):
        entered = threading.Event(); release = threading.Event(); result = {}
        def executor(_configuration):
            entered.set(); release.wait(2)
            return {"schema_version": "2.2", "scan_id": "scan-cancel", "target": {"target_id": "target-x"}, "completed_at": "2026-01-01T00:00:00Z", "partial": False, "baseline_eligible": True, "acquisition": {}}
        with tempfile.TemporaryDirectory() as directory:
            config = SCANRuntimeConfig(Path(directory) / "runtime")
            runtime = SCANRuntime(config); runtime.start()
            service = SCANService(SCANConfig(config.reports_dir, runtime=config), executor=executor, runtime=runtime)
            thread = threading.Thread(target=lambda: result.setdefault("response", service.start_scan(request())))
            thread.start(); self.assertTrue(entered.wait(1))
            service.cancel_scan("active"); release.set(); thread.join(2)
            report = result["response"].data["scan"]
        self.assertTrue(report["partial"])
        self.assertFalse(report["baseline_eligible"])
        self.assertEqual(report["termination"]["reason_code"], "operator_interrupt")
