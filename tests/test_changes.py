import copy
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scanner.changes import compare_snapshots
from scanner.contract import build_report_v2
from scanner.snapshots import build_snapshot


def snapshot(state="open", *, port=80, banner=None, ports=None):
    item = {"port": port, "transport": "tcp", "state": state, "state_evidence": {"method": "tcp_connect", "result": state}}
    if banner:
        item["banner"] = {"status": "collected", "sha256": banner}
    report = build_report_v2(target_input="192.0.2.1/32", network="192.0.2.1/32", host_results={"192.0.2.1": [item]}, ports=ports or [port], started_at="2026-08-20T00:00:00.000Z", completed_at="2026-08-20T00:00:01.000Z", duration_ms=1, ping_timeout=1.0, connect_timeout=1.0, workers=1, max_hosts=1, banners_enabled=bool(banner), banner_limits={})
    return build_snapshot(report)


class ChangeTests(unittest.TestCase):
    def test_open_to_closed_is_observed_change(self):
        result = compare_snapshots(snapshot("open"), snapshot("closed"))
        self.assertEqual(result["changes"][0]["change_type"], "endpoint_state_changed")

    def test_open_to_unknown_and_unknown_to_open_are_indeterminate(self):
        for before, after in (("open", "unknown"), ("unknown", "open")):
            with self.subTest(before=before, after=after):
                result = compare_snapshots(snapshot(before), snapshot(after))
                self.assertEqual(result["changes"], [])
                self.assertEqual(result["indeterminate"][0]["reason"], "inconclusive_state_transition")

    def test_missing_endpoint_is_not_host_removed(self):
        current = snapshot()
        current["report"]["observations"] = []
        result = compare_snapshots(snapshot(), current)
        self.assertEqual(result["changes"], [])
        self.assertIn("absence_does_not_mean_host_offline", result["indeterminate"][0]["limitation"])

    def test_configuration_difference_limits_scope(self):
        result = compare_snapshots(snapshot(port=80, ports=[80]), snapshot(port=443, ports=[443]))
        self.assertFalse(result["configuration_match"])
        self.assertEqual(result["comparison_scope"]["common_ports"], [])
        self.assertTrue(result["indeterminate"])

    def test_timestamps_and_order_do_not_create_changes(self):
        first = snapshot()
        second = copy.deepcopy(first)
        second["snapshot_id"] = "snapshot_later"
        second["report"]["completed_at"] = "2026-08-21T00:00:00.000Z"
        self.assertEqual(compare_snapshots(first, second)["changes"], [])

    def test_banner_change_is_evidence_not_update_claim(self):
        result = compare_snapshots(snapshot(banner="a"), snapshot(banner="b"))
        change = result["changes"][0]
        self.assertEqual(change["change_type"], "banner_changed")
        self.assertIn("does_not_confirm_software_change", change["limitations"][0])

    def test_different_target_is_rejected(self):
        other = snapshot()
        other["report"]["target"]["target_id"] = "target_other"
        with self.assertRaises(ValueError):
            compare_snapshots(snapshot(), other)


if __name__ == "__main__":
    unittest.main()
