import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scanner.services import service_hint


class ServiceHintTests(unittest.TestCase):
    def test_known_hint_is_explicitly_weak(self):
        self.assertEqual(service_hint(443), {"name": "https", "basis": "port_registry", "confidence": "hint"})

    def test_unknown_port_invents_nothing(self):
        self.assertIsNone(service_hint(65000))

    def test_transport_is_part_of_registry_key(self):
        self.assertIsNone(service_hint(443, "udp"))


if __name__ == "__main__":
    unittest.main()
