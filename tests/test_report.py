import json
import sys
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scanner.report import build_report, serialize_report, utc_timestamp, write_report_atomic


def sample_report(host_results=None):
    return build_report(
        target_input="192.0.2.3/29",
        network="192.0.2.0/29",
        host_port_results=host_results or {},
        ports=[22, 80],
        timestamp="2026-08-19T12:00:00.000Z",
        duration_ms=25,
        ping_timeout=1.0,
        connect_timeout=0.5,
        workers=8,
        max_hosts=4096,
    )


class ReportTests(unittest.TestCase):
    def test_schema_scanner_target_timestamp_and_metadata(self):
        report = sample_report()
        self.assertEqual(report["schema_version"], "1.0")
        self.assertEqual(report["scanner"], {"name": "SCAN", "version": "1.0.0"})
        self.assertEqual(report["network"], "192.0.2.0/29")
        self.assertEqual(
            report["target"],
            {
                "input": "192.0.2.3/29",
                "network": "192.0.2.0/29",
                "ip_version": 4,
                "candidate_hosts": 6,
            },
        )
        self.assertEqual(report["timestamp"], "2026-08-19T12:00:00.000Z")
        self.assertEqual(report["duration_ms"], 25)
        self.assertEqual(report["metadata"]["discovery"], "icmp")
        self.assertEqual(report["metadata"]["ports"], [22, 80])

    def test_utc_timestamp_is_iso_8601_utc(self):
        value = utc_timestamp(datetime(2026, 8, 19, 6, 30, tzinfo=timezone.utc))
        self.assertEqual(value, "2026-08-19T06:30:00.000Z")

    def test_zero_hosts_report_is_complete(self):
        report = sample_report()
        self.assertEqual(report["hosts"], [])
        self.assertEqual(
            report["summary"],
            {
                "active_hosts": 0,
                "hosts_scanned": 0,
                "ports_scanned": 0,
                "total_open_ports": 0,
                "total_closed_ports": 0,
                "total_errors": 0,
            },
        )

    def test_host_and_global_counts_are_coherent_and_legacy_fields_remain(self):
        report = sample_report(
            {
                "192.0.2.2": [
                    {"port": 80, "protocol": "tcp", "status": "CLOSED"},
                    {"port": 22, "protocol": "tcp", "status": "OPEN"},
                ],
                "192.0.2.1": [
                    {"port": 22, "protocol": "tcp", "status": "CLOSED"}
                ],
            }
        )
        self.assertEqual([host["host"] for host in report["hosts"]], ["192.0.2.2", "192.0.2.1"])
        first = report["hosts"][0]
        self.assertEqual(first["open_ports"], [22])
        self.assertEqual(first["open_count"], 1)
        self.assertEqual(first["closed_count"], 1)
        self.assertEqual(first["error_count"], 0)
        self.assertEqual(report["summary"]["ports_scanned"], 3)
        self.assertEqual(report["summary"]["total_open_ports"], 1)
        self.assertEqual(report["summary"]["total_closed_ports"], 2)
        self.assertEqual(report["summary"]["total_errors"], 0)

    def test_negative_duration_is_rejected(self):
        with self.assertRaises(ValueError):
            build_report(
                target_input="127.0.0.1",
                network="127.0.0.1",
                host_port_results={},
                ports=[],
                timestamp="2026-08-19T00:00:00.000Z",
                duration_ms=-1,
                ping_timeout=1.0,
                connect_timeout=1.0,
                workers=1,
                max_hosts=1,
            )

    def test_serialized_report_is_valid_json(self):
        self.assertEqual(json.loads(serialize_report(sample_report()))["schema_version"], "1.0")

    def test_atomic_file_output_and_directory_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "nested" / "scan.json"
            write_report_atomic(sample_report(), output)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["schema_version"], "1.0")
            self.assertEqual(list(output.parent.glob("*.tmp")), [])

    def test_atomic_failure_preserves_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "scan.json"
            output.write_text("existing", encoding="utf-8")
            with patch("scanner.report.serialize_report", side_effect=OSError("failure")), self.assertRaises(OSError):
                write_report_atomic({}, output)
            self.assertEqual(output.read_text(encoding="utf-8"), "existing")
            self.assertEqual(list(output.parent.glob("*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
