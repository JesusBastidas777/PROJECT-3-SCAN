import json,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"src"))
from scanner.validation import validate_file
class ValidationTests(unittest.TestCase):
 def test_valid_fixture_parse_and_bound(self):
  self.assertTrue(validate_file(Path("tests/fixtures/contracts/report-1.0.json"))["valid"])
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/"bad.json"; p.write_text("{{",encoding="utf-8"); self.assertEqual(validate_file(p)["errors"][0]["code"],"parse_error"); self.assertEqual(validate_file(p,max_bytes=1)["errors"][0]["code"],"oversized_input")
