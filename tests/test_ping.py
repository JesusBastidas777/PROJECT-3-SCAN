import subprocess
import sys
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scanner.ping import ping_host


class PingHostTests(unittest.TestCase):
    @patch("scanner.ping.subprocess.run")
    def test_host_that_responds(self, run):
        run.return_value = Mock(returncode=0)

        self.assertTrue(ping_host("127.0.0.1", timeout=0.2))
        kwargs = run.call_args.kwargs
        self.assertEqual(kwargs["stdout"], subprocess.DEVNULL)
        self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
        self.assertAlmostEqual(kwargs["timeout"], 0.7)

    @patch("scanner.ping.subprocess.run")
    def test_host_that_does_not_respond(self, run):
        run.return_value = Mock(returncode=1)
        self.assertFalse(ping_host("192.0.2.1"))

    @patch("scanner.ping.subprocess.run", side_effect=subprocess.TimeoutExpired("ping", 1))
    def test_process_timeout_is_unreachable(self, _run):
        self.assertFalse(ping_host("192.0.2.1"))

    @patch("scanner.ping.subprocess.run", side_effect=FileNotFoundError)
    def test_missing_ping_binary_is_unreachable(self, _run):
        self.assertFalse(ping_host("127.0.0.1"))

    @patch("scanner.ping.subprocess.run", side_effect=OSError("operational failure"))
    def test_operational_error_is_unreachable(self, _run):
        self.assertFalse(ping_host("127.0.0.1"))

    @patch("scanner.ping.subprocess.run")
    def test_ipv6_uses_ipv6_ping(self, run):
        run.return_value = Mock(returncode=0)
        self.assertTrue(ping_host("::1"))
        self.assertIn("-6", run.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
