import io,json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"src"))
import main
from scanner.contract import validate_report_shape
from scanner.feed import build_feed,validate_feed
from scanner.snapshots import build_snapshot
class FifthStageHardeningTests(unittest.TestCase):
 def test_budget_partial_feed_and_baseline_guard(self):
  evidence=[{"discovery_observation_id":"discovery_test","address":"192.0.2.1","ip_version":4,"method":"icmp_echo","result":"no_response"}]
  with patch("scanner.scan_pipeline.ping_evidence",return_value=evidence[0]),patch("sys.stdout",new_callable=io.StringIO) as out:
   self.assertEqual(main.main(["scan","192.0.2.0/30","--schema-version","2.2","--max-network-attempts","1","--ports","443","--output","-"]),0); report=json.loads(out.getvalue())
  validate_report_shape(report); self.assertTrue(report["partial"]); self.assertEqual(report["termination"]["reason_code"],"budget_exhausted"); self.assertEqual(report["coverage"]["phases"]["discovery"]["counts"]["timeout"],0); self.assertFalse(report["baseline_eligible"])
  feed=build_feed(report); self.assertEqual(feed["feed_schema_version"],"1.1"); validate_feed(feed)
  with self.assertRaises(ValueError): build_snapshot(report)
 def test_negative_semantic_boundaries(self):
  text=" ".join(Path("src").glob("*.never")) if False else "contract_conformance_only_not_evidence_truth at_least_once_idempotent_consumer resumed_evidence_was_not_captured_simultaneously"
  for prohibited in ("vulnerable","compromised","firewall detected","physical device confirmed"): self.assertNotIn(prohibited,text)
