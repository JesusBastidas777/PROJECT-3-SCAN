import io
import json
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import main as scan_main


class MainTests(unittest.TestCase):
    @patch("main.scan_hosts")
    def test_legacy_json_structure_is_preserved(self, scan_hosts):
        scan_hosts.return_value = {
            "192.0.2.1": [
                {"port": 22, "protocol": "tcp", "status": "OPEN"},
                {"port": 80, "protocol": "tcp", "status": "CLOSED"},
            ]
        }
        data = scan_main.build_scan_data("192.0.2.1/32", ["192.0.2.1"])
        self.assertEqual(set(data), {"network", "summary", "hosts"})
        self.assertEqual(
            set(data["hosts"][0]),
            {"host", "ports", "open_ports", "open_count", "closed_count"},
        )
        self.assertEqual(data["hosts"][0]["open_ports"], [22])
        self.assertEqual(data["summary"]["total_closed_ports"], 1)

    def test_atomic_write_replaces_complete_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "results" / "scan.json"
            scan_main.write_json_atomic({"network": "127.0.0.1/32"}, destination)
            self.assertEqual(json.loads(destination.read_text()), {"network": "127.0.0.1/32"})
            self.assertEqual(list(destination.parent.glob("*.tmp")), [])

    def test_failed_atomic_write_preserves_existing_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "scan.json"
            destination.write_text("original", encoding="utf-8")
            with patch("main.json.dump", side_effect=OSError("write failed")), self.assertRaises(OSError):
                scan_main.write_json_atomic({}, destination)
            self.assertEqual(destination.read_text(encoding="utf-8"), "original")
            self.assertEqual(list(destination.parent.glob("*.tmp")), [])

    @patch("main.Path.mkdir", side_effect=OSError("read-only filesystem"))
    def test_filesystem_error_returns_operational_code(self, _mkdir):
        with patch("main.discover_hosts", return_value=[]), patch("sys.stderr", new_callable=io.StringIO):
            self.assertEqual(scan_main.main(["127.0.0.1/32"]), scan_main.EXIT_OPERATIONAL_ERROR)

    def test_invalid_target_returns_usage_code(self):
        with patch("sys.stderr", new_callable=io.StringIO):
            self.assertEqual(scan_main.main(["invalid"]), scan_main.EXIT_USAGE)

    @patch("main.run_scan", side_effect=KeyboardInterrupt)
    def test_keyboard_interrupt_returns_130(self, _run):
        with patch("sys.stderr", new_callable=io.StringIO):
            self.assertEqual(scan_main.main(["127.0.0.1/32"]), scan_main.EXIT_INTERRUPTED)

    @patch("main.run_scan", return_value={"network": "127.0.0.1/32", "summary": {}, "hosts": []})
    def test_success_exit_code(self, _run):
        with patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(scan_main.main(["127.0.0.1/32"]), scan_main.EXIT_SUCCESS)

    def test_wrong_argument_count_returns_usage_code(self):
        with patch("sys.stderr", new_callable=io.StringIO):
            self.assertEqual(scan_main.main([]), scan_main.EXIT_USAGE)


if __name__ == "__main__":
    unittest.main()
