import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scanner.fingerprint import RULESET_VERSION, fingerprint_host, fingerprint_hosts


class FingerprintTests(unittest.TestCase):
    def test_rules_are_deterministic_and_order_independent(self):
        a = {"port": 443, "state": "open", "service": {"name": "https", "confidence": "hint"}}
        b = {"port": 80, "state": "open", "service": {"name": "http", "confidence": "hint"}}
        self.assertEqual(fingerprint_host("192.0.2.1", [a, b]), fingerprint_host("192.0.2.1", [b, a]))
        self.assertEqual(RULESET_VERSION, "1.0")

    def test_insufficient_evidence_only_reports_ip_family(self):
        values = fingerprint_host("2001:db8::1", [{"port": 80, "state": "unknown"}])
        self.assertEqual([(item["attribute"], item["value"]) for item in values], [("ip_family", "ipv6")])

    def test_conflicting_banner_does_not_upgrade_port_hint(self):
        item = {"port": 443, "state": "open", "service": {"name": "https", "confidence": "hint"}, "banner": {"text": "SSH-2.0-adversarial"}}
        values = fingerprint_host("192.0.2.1", [item])
        web = next(value for value in values if value["attribute"] == "service_family")
        self.assertEqual(web["confidence"], "low")
        self.assertNotIn("product", str(values).lower())

    def test_host_order_is_canonical_and_addresses_not_merged(self):
        values = fingerprint_hosts({"2001:db8::2": [], "192.0.2.2": [], "192.0.2.1": []})
        self.assertEqual(list(values), ["192.0.2.1", "192.0.2.2", "2001:db8::2"])


if __name__ == "__main__":
    unittest.main()
