import subprocess
import sys
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scanner.discovery import discover_host_evidence
from scanner.discovery_evidence import discovery_observation
from scanner.ping import ping_evidence


class DiscoveryEvidenceTests(unittest.TestCase):
    @patch("scanner.ping.subprocess.run")
    def test_response_and_no_response(self, run):
        run.side_effect = [Mock(returncode=0), Mock(returncode=1)]
        self.assertEqual(ping_evidence("192.0.2.1")["result"], "response")
        self.assertEqual(ping_evidence("192.0.2.2")["result"], "no_response")

    def test_stable_failures(self):
        cases = [(subprocess.TimeoutExpired("ping", 1), "timeout"), (FileNotFoundError(), "unsupported"), (OSError(), "probe_error")]
        for error, expected in cases:
            with self.subTest(expected=expected), patch("scanner.ping.subprocess.run", side_effect=error):
                self.assertEqual(ping_evidence("::1")["result"], expected)

    def test_ids_family_and_order_are_deterministic(self):
        first = discovery_observation("2001:0db8::1", "response")
        self.assertEqual(first, discovery_observation("2001:db8::1", "response"))
        self.assertEqual(first["ip_version"], 6)
        with patch("scanner.discovery.ping_evidence", side_effect=lambda host, timeout: discovery_observation(host, "response")):
            values = discover_host_evidence("192.0.2.0/30", max_workers=2)
        self.assertEqual([x["address"] for x in values], ["192.0.2.1", "192.0.2.2"])

    def test_worker_error_is_structured(self):
        with patch("scanner.discovery.ping_evidence", side_effect=RuntimeError("private message")):
            value = discover_host_evidence("192.0.2.1/32")[0]
        self.assertEqual(value["result"], "probe_error")
        self.assertEqual(value["error"], {"code": "worker_error"})
        self.assertNotIn("private", str(value))
