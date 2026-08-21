import hashlib
import socket
import unittest
from unittest.mock import MagicMock, patch

from scanner.http_probe import collect_http_metadata, collect_open_http


class FakeSocket:
    def __init__(self, responses):
        self.responses = list(responses); self.sent = b""; self.closed = False; self.endpoint = None
    def settimeout(self, value): self.timeout = value
    def connect(self, endpoint): self.endpoint = endpoint
    def sendall(self, value): self.sent += value
    def recv(self, size):
        if not self.responses: return b""
        value = self.responses.pop(0); self.responses.insert(0, value[size:]) if len(value) > size else None
        return value[:size]
    def close(self): self.closed = True


class HttpProbeTests(unittest.TestCase):
    def test_head_allowlist_ipv4_and_redirect_not_followed(self):
        sock = FakeSocket([b"HTTP/1.1 302 Found\r\nLocation: /next\r\nServer: hint\r\nSet-Cookie: secret\r\nX-Other: no\r\nContent-Length: 4\r\n\r\nbody"])
        with patch("scanner.http_probe.socket.socket", return_value=sock):
            value = collect_http_metadata("127.0.0.1", 80)
        self.assertIn(b"HEAD / HTTP/1.1\r\nHost: 127.0.0.1", sock.sent)
        self.assertEqual(value["location"], "/next"); self.assertFalse(value["redirect_followed"])
        self.assertNotIn("set-cookie", value["headers"]); self.assertEqual(value["bytes_read"], 0)

    def test_ipv6_host_literal_and_endpoint(self):
        sock = FakeSocket([b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n"])
        with patch("scanner.http_probe.socket.socket", return_value=sock):
            value = collect_http_metadata("::1", 80)
        self.assertIn(b"Host: [::1]", sock.sent); self.assertEqual(sock.endpoint, ("::1", 80, 0, 0)); self.assertEqual(value["http_version"], "1.0")

    def test_explicit_head_get_hash_and_local_truncation(self):
        head = FakeSocket([b"HTTP/1.1 405 Method Not Allowed\r\n\r\n"])
        get = FakeSocket([b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\nabcdef"])
        with patch("scanner.http_probe.socket.socket", side_effect=[head, get]):
            value = collect_http_metadata("127.0.0.1", 80, method_mode="head-get", body_hash_bytes=4)
        self.assertIn(b"Range: bytes=0-3", get.sent); self.assertEqual(value["method"], "GET")
        self.assertEqual(value["body_prefix_sha256"], hashlib.sha256(b"abcd").hexdigest()); self.assertTrue(value["truncated"])

    def test_head_never_falls_back_and_timeout_is_stable(self):
        sock = FakeSocket([b"HTTP/1.1 405 No\r\n\r\n"])
        with patch("scanner.http_probe.socket.socket", return_value=sock) as create:
            self.assertEqual(collect_http_metadata("127.0.0.1", 80)["status_code"], 405)
        create.assert_called_once()
        timed = FakeSocket([]); timed.recv = MagicMock(side_effect=socket.timeout())
        with patch("scanner.http_probe.socket.socket", return_value=timed):
            self.assertEqual(collect_http_metadata("127.0.0.1", 80)["status"], "timeout")

    def test_invalid_and_oversized_headers(self):
        invalid = FakeSocket([b"BROKEN\r\n\r\n"])
        with patch("scanner.http_probe.socket.socket", return_value=invalid):
            self.assertEqual(collect_http_metadata("127.0.0.1", 80)["error"]["code"], "invalid_status_line")
        large = FakeSocket([b"HTTP/1.1 200 OK\r\nX:" + b"a" * 600 + b"\r\n\r\n"])
        with patch("scanner.http_probe.socket.socket", return_value=large):
            self.assertEqual(collect_http_metadata("127.0.0.1", 80, max_header_bytes=512, max_header_line=128)["status"], "error")

    def test_collection_is_open_selected_bounded_and_deterministic(self):
        source = {"127.0.0.1": [{"port":80,"state":"open"},{"port":81,"state":"open"},{"port":82,"state":"closed"}]}
        with patch("scanner.http_probe.collect_http_metadata", return_value={"status":"collected","method":"HEAD"}) as probe:
            value = collect_open_http(source, ports=[80,81], workers=1, max_endpoints=1)
        self.assertEqual(probe.call_count, 1); self.assertEqual(value["127.0.0.1"][1]["http"]["status"], "skipped")
        self.assertNotIn("http", source["127.0.0.1"][0])
