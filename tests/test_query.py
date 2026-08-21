import unittest

from scanner.query import query_report


class QueryTests(unittest.TestCase):
    def test_v1_and_v21_queries(self):
        v1={"schema_version":"1.0","summary":{"total_errors":0},"hosts":[{"host":"127.0.0.1","ports":[{"port":80,"status":"OPEN"}]}]}
        self.assertEqual(query_report(v1,open_endpoints=True)["results"][0]["port"],80)
        v21={"schema_version":"2.1","summary":{},"assets":[{"asset_id":"a"}],"observations":[{"observation_id":"o","asset_id":"a","port":443,"state":"open"}],"errors":[{"code":"x"}],"coverage":{"model_version":"1.0"}}
        self.assertEqual(query_report(v21,asset_id="a")["count"],1); self.assertEqual(query_report(v21,errors=True)["count"],1)
        self.assertEqual(query_report(v21,coverage=True)["results"]["model_version"],"1.0")
        self.assertEqual(query_report(v21,evidence_ref="o")["count"],1)

    def test_unknown_and_bounded_deterministic(self):
        report={"schema_version":"2.0","summary":{},"assets":[],"observations":[{"observation_id":"b","state":"open"},{"observation_id":"a","state":"open"}],"errors":[]}
        value=query_report(report,open_endpoints=True,max_results=1)
        self.assertEqual(value["results"][0]["observation_id"],"a"); self.assertTrue(value["truncated"])
        self.assertEqual(query_report(report,asset_id="missing")["count"],0)
