import sys
from pathlib import Path
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scanner.discovery import NetworkTooLargeError, TargetValidationError, discover_hosts


class DiscoveryTests(unittest.TestCase):
    @patch("scanner.discovery.ping_host", return_value=True)
    def test_valid_ipv4_and_host_bits_are_normalized(self, ping):
        hosts = discover_hosts("192.0.2.3/29", max_workers=2)
        self.assertEqual(hosts, [f"192.0.2.{number}" for number in range(1, 7)])
        self.assertEqual(ping.call_count, 6)

    @patch("scanner.discovery.ping_host", return_value=True)
    def test_valid_ipv6(self, _ping):
        self.assertEqual(discover_hosts("2001:db8::/126"), ["2001:db8::1", "2001:db8::2", "2001:db8::3"])

    def test_invalid_target(self):
        with self.assertRaises(TargetValidationError):
            discover_hosts("not-a-network")

    def test_network_larger_than_limit_is_rejected_before_iteration(self):
        with patch("scanner.discovery.ping_host") as ping, self.assertRaises(NetworkTooLargeError):
            discover_hosts("0.0.0.0/0", max_hosts=256)
        ping.assert_not_called()

    def test_discovery_is_concurrent_and_bounded(self):
        lock = threading.Lock()
        running = 0
        maximum_running = 0

        def probe(_host, _timeout):
            nonlocal running, maximum_running
            with lock:
                running += 1
                maximum_running = max(maximum_running, running)
            time.sleep(0.02)
            with lock:
                running -= 1
            return True

        with patch("scanner.discovery.ping_host", side_effect=probe):
            discover_hosts("192.0.2.0/29", max_workers=3)
        self.assertGreater(maximum_running, 1)
        self.assertLessEqual(maximum_running, 3)

    @patch("scanner.discovery.ping_host")
    def test_order_is_deterministic_and_partial_failures_are_isolated(self, ping):
        def probe(host, _timeout):
            last = int(str(host).split(".")[-1])
            if last == 2:
                raise OSError("isolated failure")
            if last == 1:
                time.sleep(0.02)
            return last in (1, 3)

        ping.side_effect = probe
        hosts = discover_hosts("192.0.2.0/29", max_workers=6)
        self.assertEqual(hosts, ["192.0.2.1", "192.0.2.3"])


if __name__ == "__main__":
    unittest.main()
