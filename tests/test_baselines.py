import unittest

from scanner.baselines import baseline_identity


class BaselineTests(unittest.TestCase):
    def test_fingerprints_are_deterministic_and_presentation_is_separate(self):
        report = {"schema_version":"2.1","target":{"target_id":"t","network":"127.0.0.1/32","ip_version":4},"effective_configuration":{"ports":[80],"discovery_configuration":{"mode":"tcp"}}}
        first = baseline_identity(report, presentation={"output":"a"})
        second = baseline_identity(report, presentation={"output":"b"})
        self.assertEqual(first["measurement_scope_fingerprint"], second["measurement_scope_fingerprint"])
        self.assertNotEqual(first["presentation_fingerprint"], second["presentation_fingerprint"])

    def test_ordering_irrelevant_and_ipv6_changes_scope(self):
        a = {"schema_version":"2.1","target":{"target_id":"t","network":"::1/128","ip_version":6},"configuration":{"ports":[80,443]}}
        b = {"schema_version":"2.1","target":{"ip_version":6,"network":"::1/128","target_id":"t"},"configuration":{"ports":[80,443]}}
        self.assertEqual(baseline_identity(a), baseline_identity(b))
