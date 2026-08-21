import unittest

from scanner.contract import build_report_v21
from scanner.snapshots import build_snapshot, validate_snapshot


class SnapshotV11Tests(unittest.TestCase):
    def test_report_21_builds_snapshot_11(self):
        report=build_report_v21(target_input="127.0.0.1/32",network="127.0.0.1/32",host_results={},ports=[],started_at="2026-01-01T00:00:00.000Z",completed_at="2026-01-01T00:00:00.000Z",duration_ms=0,ping_timeout=1,connect_timeout=1,workers=1,max_hosts=1,banners_enabled=False,banner_limits={},discovery_configuration={"mode":"tcp"})
        self.assertEqual(report["configuration"]["discovery"], "tcp")
        snapshot=build_snapshot(report); validate_snapshot(snapshot)
        self.assertEqual(snapshot["snapshot_schema_version"], "1.1")
        self.assertIn("measurement_scope_fingerprint", snapshot)
