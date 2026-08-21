import argparse
import unittest

from scanner.configuration import ScanRequest, ResolvedScanConfiguration, effective_configuration, resolve_request


class ConfigurationTests(unittest.TestCase):
    def test_request_and_effective_configuration_are_stable(self):
        request = ScanRequest.from_namespace(argparse.Namespace(target="::1/128",schema_version="2.1",profile="evidence",profile_version="1.0"))
        self.assertEqual(request.target, "::1/128")
        first = effective_configuration({"workers":2,"ports":[443,80,443]})
        second = effective_configuration({"ports":[80,443],"workers":2})
        self.assertEqual(first, second); self.assertEqual(first.fingerprint, second.fingerprint)
        resolved=resolve_request(ScanRequest.from_namespace(argparse.Namespace(target="::1/128",schema_version="2.1",profile=None,profile_version=None,ports=[443],discovery="icmp",workers=2,max_hosts=4,ping_timeout=.1,connect_timeout=.2,output="-",history_dir=None,events_output=None,events_privacy="full",neighbor_privacy="hash-only")))
        self.assertIsInstance(resolved,ResolvedScanConfiguration); self.assertEqual(resolved.measurement.ports,(443,)); self.assertEqual(resolved.execution.workers,2)
