import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scanner import SCANConfig, SCANResponseV1, SCANService
from scanner.contract import build_report_v2
from scanner.report import write_report_atomic


def sample_report():
    return build_report_v2(
        target_input="127.0.0.1/32", network="127.0.0.1/32",
        host_results={"127.0.0.1": [{"port": 443, "transport": "tcp", "state": "open", "state_evidence": {"method": "tcp_connect", "result": "connected"}}]},
        ports=[443], started_at="2026-01-01T00:00:00Z", completed_at="2026-01-01T00:00:01Z",
        duration_ms=1000, ping_timeout=1, connect_timeout=1, workers=1,
        max_hosts=1, banners_enabled=False, banner_limits={},
    )


class ServiceTests(unittest.TestCase):
    def test_response_serialization_is_deterministic(self):
        value = SCANResponseV1(data={"z": 1, "a": 2})
        self.assertEqual(value.to_json(), value.to_json())
        self.assertEqual(list(value.to_dict()), ["schema_version", "status", "data", "errors", "metadata"])

    def test_reads_map_findings_without_probes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = sample_report()
            write_report_atomic(report, root / "report.json")
            service = SCANService(SCANConfig(root))
            with patch("scanner.scan_pipeline.discover_host_evidence") as probe:
                self.assertEqual(service.get_scan(report["scan_id"]).data["scan"]["scan_id"], report["scan_id"])
                self.assertEqual(len(service.get_findings(report["scan_id"]).data["findings"]), 1)
                service.list_scans()
                probe.assert_not_called()

    def test_capabilities_are_public(self):
        with tempfile.TemporaryDirectory() as directory:
            values = SCANService(SCANConfig(Path(directory))).capabilities().data["capabilities"]
        self.assertIn("coverage", values)
