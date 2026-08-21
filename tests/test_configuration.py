import argparse
import unittest

from scanner.configuration import ScanRequest, effective_configuration


class ConfigurationTests(unittest.TestCase):
    def test_request_and_effective_configuration_are_stable(self):
        request = ScanRequest.from_namespace(argparse.Namespace(target="::1/128",schema_version="2.1",profile="evidence",profile_version="1.0"))
        self.assertEqual(request.target, "::1/128")
        first = effective_configuration({"workers":2,"ports":[443,80,443]})
        second = effective_configuration({"ports":[80,443],"workers":2})
        self.assertEqual(first, second); self.assertEqual(first.fingerprint, second.fingerprint)
