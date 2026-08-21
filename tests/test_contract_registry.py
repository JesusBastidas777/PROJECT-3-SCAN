import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"src"))
from scanner.contract_registry import detect_contract,get_contract
class RegistryTests(unittest.TestCase):
 def test_detection_and_unknown_version(self):
  self.assertEqual(detect_contract({"schema_version":"1.0","scanner":{}}),("report","1.0")); self.assertEqual(get_contract("feed","1.0").version,"1.0")
  with self.assertRaises(ValueError): get_contract("feed","9.0")
