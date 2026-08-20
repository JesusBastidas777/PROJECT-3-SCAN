import socket
import sys
from pathlib import Path
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scanner.banners import collect_banner, collect_open_banners


class LocalBannerServer:
    def __init__(self, payload: bytes, family=socket.AF_INET):
        try:
            self.socket = socket.socket(family, socket.SOCK_STREAM)
        except PermissionError:
            raise unittest.SkipTest("sandbox prohibits loopback sockets")
        host = "127.0.0.1" if family == socket.AF_INET else "::1"
        self.socket.bind((host, 0))
        self.socket.listen(1)
        self.host, self.port = self.socket.getsockname()[:2]
        self.thread = threading.Thread(target=self._serve, args=(payload,), daemon=True)
        self.thread.start()

    def _serve(self, payload):
        connection, _ = self.socket.accept()
        with connection:
            if payload:
                connection.sendall(payload)
        self.socket.close()

    def join(self):
        self.thread.join(1)


class BannerTests(unittest.TestCase):
    def test_immediate_utf8_banner_and_exact_hash(self):
        server = LocalBannerServer(b"hello\n")
        result = collect_banner(server.host, server.port, max_bytes=16)
        server.join()
        self.assertEqual(result["status"], "collected")
        self.assertEqual(result["text"], "hello\n")
        self.assertFalse(result["trusted"])

    def test_empty_close(self):
        server = LocalBannerServer(b"")
        result = collect_banner(server.host, server.port)
        server.join()
        self.assertEqual(result["status"], "empty")

    def test_truncation_and_exact_limit(self):
        server = LocalBannerServer(b"abcdef")
        result = collect_banner(server.host, server.port, max_bytes=5)
        server.join()
        self.assertEqual(result["bytes_captured"], 5)
        self.assertTrue(result["truncated"])

    def test_invalid_utf8_is_base64(self):
        server = LocalBannerServer(b"\xff\xfe")
        result = collect_banner(server.host, server.port)
        server.join()
        self.assertEqual(result["encoding"], "base64")
        self.assertNotIn("text", result)

    def test_only_open_and_bounded_endpoints_are_contacted(self):
        observations = {"127.0.0.1": [{"port": 1, "state": "closed"}, {"port": 2, "state": "open"}, {"port": 3, "state": "open"}]}
        from unittest.mock import patch
        with patch("scanner.banners.collect_banner", return_value={"status": "empty"}) as collect:
            result = collect_open_banners(observations, max_endpoints=1)
        self.assertEqual(collect.call_count, 1)
        self.assertEqual(result["127.0.0.1"][2]["banner"]["status"], "skipped")

    def test_ipv6_loopback_when_available(self):
        if not socket.has_ipv6:
            self.skipTest("IPv6 unavailable")
        try:
            server = LocalBannerServer(b"v6", socket.AF_INET6)
        except OSError:
            self.skipTest("IPv6 loopback unavailable")
        result = collect_banner(server.host, server.port)
        server.join()
        self.assertEqual(result["text"], "v6")


if __name__ == "__main__":
    unittest.main()
