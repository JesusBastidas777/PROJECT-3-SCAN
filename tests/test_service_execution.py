import sys
from pathlib import Path
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scanner import SCANConfig, SCANService
from scanner.configuration import ScanRequest
from scanner.runtime import SCANRuntime
from scanner.runtime_paths import SCANRuntimeConfig


OPTIONS = (
    ("ports", [443]), ("workers", 1), ("max_hosts", 1), ("ping_timeout", .1),
    ("connect_timeout", .1), ("discovery", "icmp"), ("discovery_ports", [443]),
    ("include_host", []), ("exclude_host", []), ("include_cidr", []), ("exclude_cidr", []),
)


def request(**extra):
    values = dict(OPTIONS); values.update(extra)
    return ScanRequest("127.0.0.1/32", "2.2", None, None, tuple(sorted(values.items())))


class ServiceExecutionTests(unittest.TestCase):
    def test_start_uses_resolved_configuration_and_persists_report(self):
        observed = {}
        def executor(configuration):
            observed["workers"] = configuration.execution.workers
            return {"schema_version": "2.2", "scan_id": "scan-test", "target": {"target_id": "target-x"}, "completed_at": "2026-01-01T00:00:00Z", "partial": False, "baseline_eligible": True}
        with tempfile.TemporaryDirectory() as directory:
            runtime_config = SCANRuntimeConfig(Path(directory) / "runtime")
            runtime = SCANRuntime(runtime_config); runtime.start()
            service = SCANService(SCANConfig(runtime_config.reports_dir, runtime=runtime_config), executor=executor, runtime=runtime)
            response = service.start_scan(request(workers=3))
            self.assertTrue((runtime_config.reports_dir / "scan-test.json").exists())
        self.assertEqual(observed["workers"], 3)
        self.assertEqual(response.data["scan"]["scan_id"], "scan-test")

    def test_forex_requires_report_22(self):
        with tempfile.TemporaryDirectory() as directory:
            config = SCANRuntimeConfig(Path(directory) / "runtime")
            service = SCANService(SCANConfig(config.reports_dir, runtime=config))
            with self.assertRaises(Exception):
                service.start_scan(ScanRequest("127.0.0.1/32", "1.0", None, None, OPTIONS))
