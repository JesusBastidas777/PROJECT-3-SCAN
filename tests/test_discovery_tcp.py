import errno
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scanner.discovery_tcp import collect_tcp_discovery, responsive_addresses, reusable_endpoint_observations
from scanner.observations import tcp_observation


class TcpDiscoveryTests(unittest.TestCase):
    def test_connected_refused_and_timeout_semantics(self):
        values = {
            80: tcp_observation(80, "open", "connected"),
            81: tcp_observation(81, "closed", "connection_refused"),
            82: tcp_observation(82, "unknown", "timeout", error_code="timeout"),
        }
        with patch("scanner.discovery_tcp.scan_port", side_effect=lambda address, port, timeout: values[port]):
            found = collect_tcp_discovery(["192.0.2.1"], [80, 81, 82], timeout=.1, max_workers=2, max_endpoints=3)
        self.assertEqual([x["result"] for x in found], ["connected", "connection_refused", "timeout"])
        self.assertEqual(responsive_addresses(found), ["192.0.2.1"])
        self.assertEqual(set(reusable_endpoint_observations(found)), {("192.0.2.1", 80), ("192.0.2.1", 81)})

    def test_ipv6_order_and_bound(self):
        with patch("scanner.discovery_tcp.scan_port", return_value=tcp_observation(443, "closed", "connection_refused")):
            values = collect_tcp_discovery(["::1", "127.0.0.1"], [443], timeout=.1, max_workers=2, max_endpoints=2)
        self.assertEqual([x["ip_version"] for x in values], [6, 4])
        with self.assertRaises(ValueError):
            collect_tcp_discovery(["127.0.0.1", "127.0.0.2"], [80, 443], timeout=.1, max_workers=1, max_endpoints=3)

    def test_worker_error_isolated(self):
        with patch("scanner.discovery_tcp.scan_port", side_effect=OSError("private")):
            value = collect_tcp_discovery(["127.0.0.1"], [80], timeout=.1, max_workers=1, max_endpoints=1)[0]
        self.assertEqual(value["result"], "error")
        self.assertEqual(value["error"]["code"], "worker_error")
