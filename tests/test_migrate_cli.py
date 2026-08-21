import json,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"src"))
import main
class MigrateCliTests(unittest.TestCase):
 def test_unsupported_preserves_input_and_destination(self):
  source=Path("tests/fixtures/contracts/report-1.0.json"); before=source.read_bytes()
  with tempfile.TemporaryDirectory() as d: self.assertEqual(main.main(["migrate",str(source),"--to","report:2.2","--output",str(Path(d)/"out.json")]),1); self.assertFalse((Path(d)/"out.json").exists())
  self.assertEqual(source.read_bytes(),before)
