import unittest

from scanner.contract import build_report_v21
from scanner.feed import build_feed, validate_feed
from scanner.observations import tcp_observation


def report(count=2):
    items=[tcp_observation(80+i,"open","connected") for i in range(count)]
    return build_report_v21(target_input="127.0.0.1/32",network="127.0.0.1/32",host_results={"127.0.0.1":items},ports=[80+i for i in range(count)],started_at="2026-01-01T00:00:00.000Z",completed_at="2026-01-01T00:00:00.000Z",duration_ms=0,ping_timeout=1,connect_timeout=1,workers=1,max_hosts=1,banners_enabled=False,banner_limits={})


class FeedTests(unittest.TestCase):
    def test_contract_determinism_privacy_and_refs(self):
        value=build_feed(report()); validate_feed(value); self.assertEqual(value,build_feed(report()))
        self.assertIn("address_sha256",value["asset_summaries"][0]["addresses"][0]); self.assertNotIn("address",value["asset_summaries"][0]["addresses"][0])
        full=build_feed(report(),privacy="full"); self.assertEqual(full["asset_summaries"][0]["addresses"][0]["address"],"127.0.0.1")
        self.assertFalse(value["report_ref"].startswith("/"))

    def test_limits_and_byte_budget_are_explicit(self):
        value=build_feed(report(4),max_endpoints=1); self.assertTrue(value["truncated"]); self.assertEqual(value["omitted_counts"]["endpoints"],3)
        size=len(__import__('scanner.contract',fromlist=['canonical_json']).canonical_json(value).encode())+1
        exact=build_feed(report(4),max_endpoints=1,max_bytes=size); self.assertEqual(exact,value)
        with self.assertRaises(ValueError): build_feed(report(),max_bytes=10)
