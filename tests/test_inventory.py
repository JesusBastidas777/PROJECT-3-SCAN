import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scanner.inventory import asset_id, build_inventory, target_id


class InventoryTests(unittest.TestCase):
    def test_ipv4_ipv6_normalization_and_order(self):
        values = build_inventory("192.0.2.7/24", {"2001:0db8::1": [], "192.0.2.2": []})
        self.assertEqual(values[0]["addresses"][0]["address"], "192.0.2.2")
        self.assertEqual(values[1]["addresses"][0]["address"], "2001:db8::1")

    def test_stable_scoped_ids(self):
        self.assertEqual(asset_id("192.0.2.0/24", "192.0.2.1"), asset_id("192.0.2.7/24", "192.0.2.1"))
        self.assertNotEqual(asset_id("192.0.2.0/24", "192.0.2.1"), asset_id("192.0.2.0/24", "192.0.2.2"))
        self.assertTrue(target_id("192.0.2.0/24").startswith("target_"))

    def test_endpoints_are_sorted_and_deduplicated(self):
        values = build_inventory("192.0.2.0/24", {"192.0.2.1": [
            {"port": 443, "transport": "tcp", "state": "open"},
            {"port": 22, "transport": "tcp", "state": "closed"},
            {"port": 443, "transport": "tcp", "state": "unknown"},
        ]})
        self.assertEqual([(x["transport"], x["port"]) for x in values[0]["endpoints"]], [("tcp", 22), ("tcp", 443)])
        self.assertEqual(values[0]["endpoints"][1]["state"], "unknown")

    def test_distinct_addresses_are_never_merged_or_called_physical(self):
        values = build_inventory("192.0.2.0/24", {"192.0.2.1": [], "192.0.2.2": []})
        self.assertEqual(len(values), 2)
        self.assertFalse(values[0]["identity"]["physical_device"])


if __name__ == "__main__":
    unittest.main()
