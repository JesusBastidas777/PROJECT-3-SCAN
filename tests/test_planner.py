import argparse, unittest, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"src"))
from scanner.configuration import ScanRequest, resolve_request
from scanner.plan_contract import validate_plan
from scanner.planner import build_scan_plan, MAX_LISTED_PLAN_HOSTS
from scanner.scan_parser import create_parser
class PlannerTests(unittest.TestCase):
 def test_ipv4_ipv6_determinism_and_bound(self):
  for target in ("192.0.2.0/30","2001:db8::/126"):
   args=create_parser().parse_args([target,"--max-hosts","8"]); c=resolve_request(ScanRequest.from_namespace(args)); a=build_scan_plan(c); b=build_scan_plan(c); self.assertEqual(a,b); validate_plan(a); self.assertLessEqual(len(a["target"]["selected_hosts"]["items"]),MAX_LISTED_PLAN_HOSTS); self.assertEqual(a["potential_maximum_network_attempts"]["kind"],"structural_upper_bound_not_prediction")
