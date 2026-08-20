import hashlib
import socket
import ssl
import sys
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from scanner.tls import collect_open_tls, collect_tls_metadata


class TlsTests(unittest.TestCase):
    def _success(self, address="127.0.0.1"):
        raw = MagicMock()
        raw.__enter__.return_value = raw
        secured = MagicMock()
        secured.__enter__.return_value = secured
        secured.version.return_value = "TLSv1.3"
        secured.cipher.return_value = ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)
        secured.getpeercert.return_value = b"certificate"
        context = MagicMock()
        context.wrap_socket.return_value = secured
        with patch("scanner.tls.socket.socket", return_value=raw), patch("scanner.tls.ssl.SSLContext", return_value=context):
            result = collect_tls_metadata(address, 443, .1, .2)
        return result, context

    def test_handshake_hash_only_and_no_sni(self):
        result, context = self._success()
        self.assertEqual(result["certificate_sha256"], hashlib.sha256(b"certificate").hexdigest())
        self.assertFalse(result["trusted"])
        self.assertFalse(result["validation_performed"])
        self.assertEqual(context.wrap_socket.call_args.kwargs["server_hostname"], None)

    def test_ipv6_and_failures(self):
        result, _ = self._success("::1")
        self.assertEqual(result["status"], "collected")
        raw = MagicMock(); raw.__enter__.return_value = raw; raw.connect.side_effect = socket.timeout()
        with patch("scanner.tls.socket.socket", return_value=raw):
            self.assertEqual(collect_tls_metadata("127.0.0.1", 443, .1, .1)["status"], "timeout")

    def test_only_open_selected_bounded_endpoints(self):
        values = {"127.0.0.1": [{"port": 443, "state": "open"}, {"port": 8443, "state": "open"}, {"port": 80, "state": "closed"}]}
        with patch("scanner.tls.collect_tls_metadata", return_value={"status": "collected"}) as probe:
            result = collect_open_tls(values, ports=[443, 8443], max_endpoints=1)
        self.assertEqual(probe.call_count, 1)
        self.assertEqual(result["127.0.0.1"][1]["tls"]["status"], "skipped")

    def test_limits(self):
        with self.assertRaises(ValueError):
            collect_open_tls({}, workers=17)
