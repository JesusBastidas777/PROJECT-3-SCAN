import unittest

from scanner.comparability import build_comparison_v2, validate_comparison_v2
from scanner.contract import build_report_v2
from scanner.snapshots import build_snapshot


def snapshot(*, ports=(80,), timeout=1, mode="icmp", state="open", privacy="hash-only"):
    item = {"port":ports[0],"transport":"tcp","state":state,"state_evidence":{"method":"tcp_connect","result":"connected" if state == "open" else "connection_refused"}}
    report = build_report_v2(target_input="127.0.0.1/32",network="127.0.0.1/32",host_results={"127.0.0.1":[item]},ports=ports,started_at="2026-01-01T00:00:00.000Z",completed_at="2026-01-01T00:00:00.000Z",duration_ms=0,ping_timeout=1,connect_timeout=timeout,workers=1,max_hosts=1,banners_enabled=False,banner_limits={},discovery_configuration={"mode":mode,"privacy":privacy})
    return build_snapshot(report)


class ComparabilityTests(unittest.TestCase):
    def test_same_scope_comparable_and_state_change(self):
        value = build_comparison_v2(snapshot(state="open"), snapshot(state="closed"))
        validate_comparison_v2(value); self.assertEqual(value["comparability"], "comparable"); self.assertEqual(value["changes_summary"]["total"], 1)

    def test_strict_mismatch_never_reports_network_change(self):
        for current in (snapshot(timeout=2), snapshot(mode="tcp"), snapshot(ports=(443,))):
            value = build_comparison_v2(snapshot(), current)
            self.assertEqual(value["comparability"], "incomparable"); self.assertEqual(value["changes"], [])
            self.assertTrue(any(item["reason"] == "measurement_scope_mismatch" for item in value["indeterminate"]))

    def test_common_scope_is_explicitly_partial(self):
        value = build_comparison_v2(snapshot(ports=(80,443)), snapshot(ports=(80,)), policy="common-scope", explain=True)
        self.assertEqual(value["comparability"], "partially_comparable"); self.assertIn("phase_comparability", value)

    def test_profile_and_privacy_changes_fingerprint(self):
        left, right = snapshot(privacy="full"), snapshot(privacy="hash-only")
        self.assertNotEqual(build_comparison_v2(left,right)["baseline_identity"]["measurement_scope_fingerprint"], build_comparison_v2(left,right)["current_identity"]["measurement_scope_fingerprint"])
