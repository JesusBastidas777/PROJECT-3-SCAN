import argparse
import io
import json
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import main as scan_main
from scanner.discovery import TargetValidationError


REPORT = {
    "schema_version": "1.0",
    "scanner": {"name": "SCAN", "version": "1.0.0"},
    "network": "127.0.0.1/32",
    "target": {"input": "127.0.0.1/32", "network": "127.0.0.1/32", "ip_version": 4, "candidate_hosts": 1},
    "timestamp": "2026-08-19T00:00:00.000Z",
    "duration_ms": 0,
    "summary": {"active_hosts": 0, "hosts_scanned": 0, "ports_scanned": 0, "total_open_ports": 0, "total_closed_ports": 0, "total_errors": 0},
    "hosts": [],
    "metadata": {"discovery": "icmp", "ports": [22, 80], "ping_timeout_seconds": 1.0, "connect_timeout_seconds": 1.0, "workers": 4, "max_hosts": 4096},
}


class CliTests(unittest.TestCase):
    def test_schema_version_selection_defaults_to_one(self):
        parser = scan_main.create_parser()
        self.assertEqual(parser.parse_args(["127.0.0.1"]).schema_version, "1.0")
        self.assertEqual(parser.parse_args(["127.0.0.1", "--schema-version", "2.0"]).schema_version, "2.0")

    def test_help_exits_successfully(self):
        with patch("sys.stdout", new_callable=io.StringIO) as stdout, self.assertRaises(SystemExit) as raised:
            scan_main.main(["--help"])
        self.assertEqual(raised.exception.code, 0)
        self.assertIn("--connect-timeout", stdout.getvalue())

    def test_valid_target_and_all_options_reach_collection(self):
        with patch("main.collect_report", return_value=REPORT) as collect, patch("sys.stdout", new_callable=io.StringIO):
            code = scan_main.main([
                "127.0.0.1/32", "--ports", "22,80,22", "--workers", "4",
                "--ping-timeout", "0.2", "--connect-timeout", "0.3",
                "--max-hosts", "8", "--output", "-",
            ])
        self.assertEqual(code, 0)
        args = collect.call_args.args[0]
        self.assertEqual(args.ports, [22, 80])
        self.assertEqual(args.workers, 4)
        self.assertEqual(args.ping_timeout, 0.2)
        self.assertEqual(args.connect_timeout, 0.3)
        self.assertEqual(args.max_hosts, 8)

    def test_invalid_target_returns_usage_code(self):
        with patch("main.collect_report", side_effect=TargetValidationError("invalid")), patch("sys.stderr", new_callable=io.StringIO):
            self.assertEqual(scan_main.main(["invalid"]), scan_main.EXIT_USAGE)

    def test_oversized_target_is_rejected_before_discovery(self):
        with patch("main.discover_hosts") as discover, patch(
            "sys.stderr", new_callable=io.StringIO
        ):
            code = scan_main.main(["0.0.0.0/0", "--max-hosts", "4096"])
        self.assertEqual(code, scan_main.EXIT_USAGE)
        discover.assert_not_called()

    def test_invalid_port_workers_timeouts_and_max_hosts_are_rejected(self):
        cases = [
            ["127.0.0.1", "--ports", "0"],
            ["127.0.0.1", "--ports", "text"],
            ["127.0.0.1", "--workers", "0"],
            ["127.0.0.1", "--workers", "257"],
            ["127.0.0.1", "--ping-timeout", "0"],
            ["127.0.0.1", "--connect-timeout", "nan"],
            ["127.0.0.1", "--max-hosts", "0"],
        ]
        for arguments in cases:
            with self.subTest(arguments=arguments), patch("sys.stderr", new_callable=io.StringIO), self.assertRaises(SystemExit) as raised:
                scan_main.main(arguments)
            self.assertEqual(raised.exception.code, 2)

    @patch("main.collect_report", return_value=REPORT)
    def test_stdout_output_is_exclusively_valid_json(self, _collect):
        with patch("sys.stdout", new_callable=io.StringIO) as stdout, patch("sys.stderr", new_callable=io.StringIO) as stderr:
            code = scan_main.main(["127.0.0.1/32", "--output", "-"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout.getvalue()), REPORT)
        self.assertEqual(stderr.getvalue(), "")

    @patch("main.collect_report", return_value=REPORT)
    def test_file_output_creates_directories_and_uses_stderr(self, _collect):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "nested" / "scan.json"
            with patch("sys.stdout", new_callable=io.StringIO) as stdout, patch("sys.stderr", new_callable=io.StringIO) as stderr:
                code = scan_main.main(["127.0.0.1/32", "--output", str(output)])
            self.assertEqual(code, 0)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("report written", stderr.getvalue())
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), REPORT)

    @patch("main.collect_report", return_value=REPORT)
    @patch("main.write_report_atomic", side_effect=OSError("read-only"))
    def test_filesystem_failure_returns_operational_code(self, _write, _collect):
        with patch("sys.stderr", new_callable=io.StringIO):
            code = scan_main.main(["127.0.0.1/32", "--output", "scan.json"])
        self.assertEqual(code, scan_main.EXIT_OPERATIONAL_ERROR)

    @patch("main.collect_report", side_effect=KeyboardInterrupt)
    def test_keyboard_interrupt_returns_130(self, _collect):
        with patch("sys.stderr", new_callable=io.StringIO):
            self.assertEqual(scan_main.main(["127.0.0.1/32"]), scan_main.EXIT_INTERRUPTED)

    @patch("main.time.monotonic", side_effect=[10.0, 10.025])
    @patch("main.utc_timestamp", return_value="2026-08-19T00:00:00.000Z")
    @patch("main.scan_hosts", return_value={"127.0.0.1": []})
    @patch("main.discover_hosts", return_value=["127.0.0.1"])
    def test_collection_builds_nonnegative_duration(self, _discover, _scan, _timestamp, _clock):
        args = argparse.Namespace(
            target="127.0.0.1/32", ports=[22], workers=2,
            ping_timeout=0.2, connect_timeout=0.3, max_hosts=2, output="-",
            collect_banners=False, banner_workers=2, banner_max_endpoints=8,
            banner_max_bytes=128, banner_read_timeout=0.2,
            schema_version="1.0",
        )
        report = scan_main.collect_report(args)
        self.assertEqual(report["duration_ms"], 25)
        self.assertEqual(report["summary"]["active_hosts"], 1)


if __name__ == "__main__":
    unittest.main()
