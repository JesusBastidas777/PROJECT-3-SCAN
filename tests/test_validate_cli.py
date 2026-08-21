import io,sys,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"src"))
import main
class ValidateCliTests(unittest.TestCase):
 def test_json_offline_read_only(self):
  path=Path("tests/fixtures/contracts/feed-1.0.json"); before=path.read_bytes()
  with patch("socket.socket",side_effect=AssertionError("network")),patch("sys.stdout",new_callable=io.StringIO) as out: self.assertEqual(main.main(["validate",str(path),"--format","json"]),0); self.assertIn('"valid": true',out.getvalue())
  self.assertEqual(path.read_bytes(),before)
