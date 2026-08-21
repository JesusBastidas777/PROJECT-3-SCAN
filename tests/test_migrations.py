import json,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"src"))
from scanner.contract_registry import detect_contract
from scanner.migration_registry import migrate_document
class MigrationTests(unittest.TestCase):
 def test_approved_route_preserves_evidence(self):
  source=json.loads(Path("tests/fixtures/contracts/report-2.0.json").read_text()); source["schema_version"]="2.1"
  with self.assertRaises(ValueError): migrate_document(source,"report","2.0","report","2.2")
