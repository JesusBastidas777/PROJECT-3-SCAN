import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"src"))
from scanner.target_policy import apply_target_policy
class TargetPolicyTests(unittest.TestCase):
 def test_include_exclude_overlap_and_scope(self):
  value=apply_target_policy("192.0.2.0/29",include_cidrs=["192.0.2.0/30"],exclude_hosts=["192.0.2.2"]); self.assertEqual(value.selected,("192.0.2.1",)); self.assertIn("192.0.2.2",value.excluded)
  with self.assertRaises(ValueError): apply_target_policy("192.0.2.0/24",include_hosts=["192.0.3.1"])
 def test_edge_prefixes_and_families(self):
  self.assertEqual(apply_target_policy("192.0.2.1/32").selected,("192.0.2.1",)); self.assertEqual(len(apply_target_policy("2001:db8::/127").selected),2)
  with self.assertRaises(ValueError): apply_target_policy("2001:db8::/64",exclude_hosts=["192.0.2.1"])
