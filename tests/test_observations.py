import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scanner.observations import legacy_port_result, tcp_observation


class ObservationTests(unittest.TestCase):
    def test_error_contains_only_stable_code(self):
        value = tcp_observation(22, "error", "local_error", error_code="local_error")
        self.assertEqual(value["error"], {"code": "local_error"})

    def test_schema_one_projection_is_frozen(self):
        value = tcp_observation(80, "unknown", "timeout", error_code="timeout")
        self.assertEqual(legacy_port_result(value), {"port": 80, "protocol": "tcp", "status": "CLOSED"})

    def test_invalid_state_is_rejected(self):
        with self.assertRaises(ValueError):
            tcp_observation(80, "filtered", "timeout")


if __name__ == "__main__":
    unittest.main()
