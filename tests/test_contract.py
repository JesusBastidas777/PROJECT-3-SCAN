import json
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from scanner.contract import build_report_v2, canonical_content, canonical_json, semantic_hash, validate_report_shape


class ContractTests(unittest.TestCase):
    def test_golden_fixtures_have_valid_required_shapes(self):
        for name in ("report-1.0.json", "report-2.0.json"):
            value = json.loads((ROOT / "tests" / "fixtures" / "contracts" / name).read_text())
            validate_report_shape(value)

    def test_v2_is_deterministic_and_has_known_states(self):
        kwargs = dict(target_input="127.0.0.1/32", network="127.0.0.1/32", host_results={"127.0.0.1": [{"port": 80, "transport": "tcp", "state": "open", "state_evidence": {"method": "tcp_connect", "result": "connected"}}]}, ports=[80], started_at="2026-08-20T00:00:00.000Z", completed_at="2026-08-20T00:00:01.000Z", duration_ms=1000, ping_timeout=1.0, connect_timeout=1.0, workers=1, max_hosts=1, banners_enabled=False, banner_limits={})
        first = build_report_v2(**kwargs)
        second = build_report_v2(**kwargs)
        self.assertEqual(first, second)
        validate_report_shape(first)
        self.assertEqual(first["summary"]["states"], {"open": 1, "closed": 0, "unknown": 0, "error": 0})

    def test_canonicalization_ignores_volatile_fields_and_key_order(self):
        a = {"duration_ms": 1, "started_at": "a", "value": {"b": 2, "a": 1}}
        b = {"duration_ms": 9, "started_at": "b", "value": {"a": 1, "b": 2}}
        self.assertEqual(semantic_hash(canonical_content(a)), semantic_hash(canonical_content(b)))
        self.assertEqual(canonical_json({"b": 2, "a": 1}), '{"a":1,"b":2}')

    def test_unknown_version_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_report_shape({"schema_version": "3.0"})


if __name__ == "__main__":
    unittest.main()
