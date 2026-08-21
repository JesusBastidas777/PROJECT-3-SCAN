import unittest

from scanner.coverage import PHASE_ORDER, build_coverage, phase_descriptor, validate_coverage
from scanner.contract import build_report_v2, build_report_v21, validate_report_shape


class CoverageTests(unittest.TestCase):
    def test_supported_disabled_unsupported_and_complete(self):
        complete = phase_descriptor("x", supported=True, backend="mock", enabled=True, eligible=1, attempted=1, observed=1, effective_limits={"workers": 1})
        self.assertTrue(complete["complete_within_configured_scope"])
        self.assertFalse(phase_descriptor("x", supported=True, backend="mock", enabled=False)["complete_within_configured_scope"])
        unsupported = phase_descriptor("x", supported=False, backend="none", enabled=False, reason="missing")
        self.assertEqual(unsupported["support"], {"status": "unsupported", "reason": "missing"})

    def test_timeout_error_truncation_and_invariants(self):
        value = phase_descriptor("x", supported=True, backend="mock", enabled=True, eligible=4, attempted=3, observed=1, timeout=1, error=1, skipped=1, truncated=True)
        self.assertEqual((value["timeout"], value["error"], value["skipped"]), (1, 1, 1))
        self.assertFalse(value["complete_within_configured_scope"])
        with self.assertRaises(ValueError):
            phase_descriptor("x", supported=True, backend="mock", enabled=True, eligible=1, attempted=2)

    def test_build_is_ordered_and_counts_ipv4_ipv6(self):
        discovery = [
            {"discovery_observation_id": "d4", "result": "response"},
            {"discovery_observation_id": "d6", "result": "timeout"},
        ]
        coverage = build_coverage(observations=[], discovery_observations=discovery, name_observations=[], configuration={"ports": [], "workers": 2, "max_hosts": 2, "ping_timeout_seconds": 1, "connect_timeout_seconds": 1})
        self.assertEqual(tuple(coverage["phases"]), PHASE_ORDER)
        self.assertEqual(coverage["phases"]["discovery"]["observed"], 1)
        self.assertEqual(coverage["phases"]["discovery"]["timeout"], 1)
        validate_coverage(coverage)

    def test_unsupported_runtime_is_not_target_observation(self):
        coverage = build_coverage(observations=[], discovery_observations=[{"discovery_observation_id": "d", "result": "unsupported"}], name_observations=[], configuration={})
        phase = coverage["phases"]["discovery"]
        self.assertEqual(phase["support"]["status"], "unsupported")
        self.assertNotIn("host", phase)

    def test_report_versions_two_and_two_one_remain_independent(self):
        arguments = dict(target_input="127.0.0.1/32", network="127.0.0.1/32", host_results={}, ports=[], started_at="2026-01-01T00:00:00.000Z", completed_at="2026-01-01T00:00:01.000Z", duration_ms=1000, ping_timeout=1.0, connect_timeout=1.0, workers=1, max_hosts=1, banners_enabled=False, banner_limits={})
        legacy = build_report_v2(**arguments)
        current = build_report_v21(**arguments)
        self.assertEqual(legacy["schema_version"], "2.0")
        self.assertNotIn("coverage", legacy)
        self.assertEqual(current["schema_version"], "2.1")
        validate_report_shape(legacy)
        validate_report_shape(current)
