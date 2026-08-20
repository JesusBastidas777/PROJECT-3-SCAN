import socket
import sys
from pathlib import Path
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scanner.ports import scan_hosts, scan_port, scan_ports


class FakeSocket:
    def __init__(self, result=0, error=None):
        self.result = result
        self.error = error
        self.timeout = None
        self.closed = False
        self.endpoint = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.closed = True

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect_ex(self, endpoint):
        self.endpoint = endpoint
        if self.error:
            raise self.error
        return self.result


class ScanPortTests(unittest.TestCase):
    def test_open_port_ipv4_and_timeout(self):
        fake = FakeSocket(result=0)
        with patch("scanner.ports.socket.socket", return_value=fake) as factory:
            result = scan_port("127.0.0.1", 80, timeout=0.25)

        self.assertEqual(result["state"], "open")
        self.assertEqual(result["state_evidence"]["result"], "connected")
        self.assertEqual(result["service"]["confidence"], "hint")
        self.assertEqual(fake.timeout, 0.25)
        self.assertTrue(fake.closed)
        factory.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)

    def test_connection_refused_is_closed(self):
        fake = FakeSocket(result=111)
        with patch("scanner.ports.socket.socket", return_value=fake):
            self.assertEqual(scan_port("127.0.0.1", 81)["state"], "closed")
        self.assertTrue(fake.closed)

    def test_timeout_is_closed_and_socket_is_closed(self):
        fake = FakeSocket(error=socket.timeout("timed out"))
        with patch("scanner.ports.socket.socket", return_value=fake):
            self.assertEqual(scan_port("127.0.0.1", 81)["state"], "unknown")
        self.assertTrue(fake.closed)

    def test_socket_exception_is_closed_and_socket_is_closed(self):
        fake = FakeSocket(error=OSError("network error"))
        with patch("scanner.ports.socket.socket", return_value=fake):
            self.assertEqual(scan_port("127.0.0.1", 81)["state"], "error")
        self.assertTrue(fake.closed)

    def test_ipv6_uses_ipv6_socket_and_endpoint(self):
        fake = FakeSocket(result=0)
        with patch("scanner.ports.socket.socket", return_value=fake) as factory:
            result = scan_port("::1", 443)
        self.assertEqual(result["state"], "open")
        factory.assert_called_once_with(socket.AF_INET6, socket.SOCK_STREAM)
        self.assertEqual(fake.endpoint, ("::1", 443, 0, 0))

    def test_invalid_and_non_integer_ports_are_rejected(self):
        for port in (0, 65536, "80", True):
            with self.subTest(port=port), self.assertRaises(ValueError):
                scan_ports("127.0.0.1", [port])

    @patch("scanner.ports.scan_port")
    def test_duplicate_ports_removed_and_order_deterministic(self, scan):
        release = threading.Event()

        def result(_host, port, _timeout):
            if port == 80:
                release.wait(0.1)
            else:
                release.set()
            return {"port": port, "transport": "tcp", "state": "closed"}

        scan.side_effect = result
        results = scan_ports("127.0.0.1", [80, 22, 80, 443], max_workers=3)
        self.assertEqual([item["port"] for item in results], [80, 22, 443])
        self.assertEqual(scan.call_count, 3)

    @patch("scanner.ports.scan_port")
    def test_failed_future_does_not_abort_host(self, scan):
        scan.side_effect = [RuntimeError("failure"), {"port": 80, "transport": "tcp", "state": "open"}]
        results = scan_ports("127.0.0.1", [22, 80], max_workers=2)
        self.assertEqual([item["state"] for item in results], ["error", "open"])

    @patch("scanner.ports.scan_port")
    def test_multi_host_scan_uses_one_global_executor_and_preserves_order(self, scan):
        scan.side_effect = lambda host, port, timeout: {
            "port": port,
            "protocol": "tcp",
            "state": "open" if host == "127.0.0.1" else "closed",
        }
        results = scan_hosts(["127.0.0.1", "::1"], [443, 22], max_workers=2)
        self.assertEqual(list(results), ["127.0.0.1", "::1"])
        self.assertEqual([item["port"] for item in results["::1"]], [443, 22])
        self.assertEqual(scan.call_count, 4)


if __name__ == "__main__":
    unittest.main()
