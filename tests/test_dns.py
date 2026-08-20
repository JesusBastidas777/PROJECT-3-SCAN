import socket
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from scanner.dns import collect_name_observations, normalize_hostname, reverse_dns


class DnsTests(unittest.TestCase):
    def test_resolved_normalized_unicode_and_duplicates(self):
        resolver = lambda address: ("B\N{LATIN SMALL LETTER U WITH DIAERESIS}CHER.Example.", ["xn--bcher-kva.example", "Alias.EXAMPLE."], [address])
        value = reverse_dns("192.0.2.1", 1, resolver)
        self.assertEqual(value["status"], "resolved")
        self.assertEqual(value["names"], ["alias.example", "xn--bcher-kva.example"])
        self.assertFalse(value["trusted"])

    def test_no_name_timeout_and_error(self):
        for error, status in ((socket.herror(), "no_name"), (socket.timeout(), "timeout"), (OSError(), "error")):
            with self.subTest(status=status):
                value = reverse_dns("::1", 1, lambda address, error=error: (_ for _ in ()).throw(error))
                self.assertEqual(value["status"], status)

    def test_order_deduplication_and_limit(self):
        resolver = lambda address: (f"host-{address}.example", [], [address])
        values = collect_name_observations(["2001:db8::1", "192.0.2.2", "192.0.2.2"], max_assets=1, resolver=resolver)
        self.assertEqual([x["address"] for x in values], ["192.0.2.2", "2001:db8::1"])
        self.assertEqual(values[1]["status"], "skipped")

    def test_timeout_is_documented_best_effort(self):
        value = reverse_dns("127.0.0.1", 1, lambda address: ("localhost", [], [address]))
        self.assertEqual(value["timeout_guarantee"], "best_effort")
