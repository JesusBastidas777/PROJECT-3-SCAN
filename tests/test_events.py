import json
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from scanner.contract import build_report_v2
from scanner.events import MAX_EVENT_BYTES, events_from_report, validate_event


def report(count=1):
    items = [{"port": 1000 + index, "transport": "tcp", "state": "open", "state_evidence": {"method": "tcp_connect", "result": "connected"}} for index in range(count)]
    return build_report_v2(target_input="127.0.0.1/32", network="127.0.0.1/32", host_results={"127.0.0.1": items}, ports=[item["port"] for item in items], started_at="2026-08-20T00:00:00.000Z", completed_at="2026-08-20T00:00:01.000Z", duration_ms=1, ping_timeout=1.0, connect_timeout=1.0, workers=1, max_hosts=1, banners_enabled=False, banner_limits={})


class EventTests(unittest.TestCase):
    def test_golden_fixture_and_generated_events_validate(self):
        validate_event(json.loads((ROOT / "tests/fixtures/contracts/event-1.0.json").read_text()))
        for event in events_from_report(report()):
            validate_event(event)

    def test_ids_and_deduplication_are_stable(self):
        self.assertEqual(events_from_report(report()), events_from_report(report()))

    def test_limit_is_explicit_not_silent(self):
        events = events_from_report(report(5), max_events=3)
        self.assertEqual(len(events), 3)
        self.assertEqual(events[-1]["event_type"], "scan.partial")
        self.assertGreater(events[-1]["observation"]["events_omitted"], 0)

    def test_evidence_references_exist_and_no_empty_optional_fields(self):
        value = report()
        known = {item["observation_id"] for item in value["observations"]}
        for event in events_from_report(value):
            self.assertTrue(set(event["evidence_refs"]) <= known)
            self.assertNotIn("sequence", event)
            self.assertLessEqual(len(str(event).encode()), MAX_EVENT_BYTES)


if __name__ == "__main__":
    unittest.main()
