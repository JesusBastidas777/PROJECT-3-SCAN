import json,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"src"))
from scanner.outbox import acknowledge,claim,enqueue,list_items,recover,show
class OutboxTests(unittest.TestCase):
 def test_at_least_once_claim_recover_ack_and_duplicate(self):
  payload=json.loads(Path("tests/fixtures/contracts/feed-1.0.json").read_text())
  with tempfile.TemporaryDirectory() as d:
   root=Path(d); item=enqueue(root,payload); self.assertEqual(len(list_items(root)),1)
   with self.assertRaises(FileExistsError): enqueue(root,payload)
   claimed=claim(root,item["item_id"],consumer_id="FOREX",lease_seconds=1); self.assertEqual(show(root,item["item_id"])[0],"processing"); self.assertEqual(recover(root,now=claimed["claim"]["lease_deadline_unix"]+1),[item["item_id"]])
   claimed=claim(root,item["item_id"],consumer_id="FOREX"); token=claimed["claim"]["claim_token"]; ack=acknowledge(root,item["item_id"],claim_token=token,content_hash=item["content_hash"]); self.assertEqual(acknowledge(root,item["item_id"],claim_token=token,content_hash=item["content_hash"])["item_id"],item["item_id"])
 def test_bounded_listing(self):
  payload=json.loads(Path("tests/fixtures/contracts/feed-1.0.json").read_text())
  with tempfile.TemporaryDirectory() as d: enqueue(Path(d),payload); self.assertEqual(len(list_items(Path(d),limit=1)),1)
