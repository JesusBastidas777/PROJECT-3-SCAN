import io,json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"src"))
import main
class OutboxCliTests(unittest.TestCase):
 def test_enqueue_list_is_local(self):
  with tempfile.TemporaryDirectory() as d,patch("socket.socket",side_effect=AssertionError("network")),patch("sys.stdout",new_callable=io.StringIO) as out:
   self.assertEqual(main.main(["outbox","--root",d,"enqueue","tests/fixtures/contracts/feed-1.0.json"]),0); item=json.loads(out.getvalue()); out.seek(0); out.truncate(0); self.assertEqual(main.main(["outbox","--root",d,"list","--limit","1"]),0); self.assertEqual(len(json.loads(out.getvalue())["items"]),1); self.assertEqual(item["delivery_semantics"],"at_least_once_idempotent_consumer")
