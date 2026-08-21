"""Local FOREX outbox management CLI."""
import argparse,json
from pathlib import Path
import sys
from collections.abc import Sequence
from scanner.loaders import load_json_document
from scanner.outbox import acknowledge,claim,enqueue,fail,list_items,recover,show
from scanner.report import serialize_report
def outbox_main(argv: Sequence[str]) -> int:
 p=argparse.ArgumentParser(prog="SCAN outbox"); p.add_argument("--root",type=Path,required=True); sub=p.add_subparsers(dest="command",required=True)
 e=sub.add_parser("enqueue"); e.add_argument("payload",type=Path); e.add_argument("--privacy",choices=("full","hash-only"),default="hash-only")
 l=sub.add_parser("list"); l.add_argument("--state",default="pending"); l.add_argument("--limit",type=int,default=100); l.add_argument("--offset",type=int,default=0)
 s=sub.add_parser("show"); s.add_argument("item_id"); c=sub.add_parser("claim"); c.add_argument("item_id"); c.add_argument("--consumer-id",required=True); c.add_argument("--lease-seconds",type=float,default=60)
 a=sub.add_parser("ack"); a.add_argument("item_id"); a.add_argument("--token",required=True); a.add_argument("--content-hash",required=True)
 f=sub.add_parser("fail"); f.add_argument("item_id"); f.add_argument("--token",required=True); sub.add_parser("recover")
 x=p.parse_args(argv)
 try:
  if x.command=="enqueue": value=enqueue(x.root,load_json_document(x.payload),privacy=x.privacy)
  elif x.command=="list": value={"items":list_items(x.root,state=x.state,limit=x.limit,offset=x.offset)}
  elif x.command=="show": state,item=show(x.root,x.item_id); value={"state":state,"item":item}
  elif x.command=="claim": value=claim(x.root,x.item_id,consumer_id=x.consumer_id,lease_seconds=x.lease_seconds)
  elif x.command=="ack": value=acknowledge(x.root,x.item_id,claim_token=x.token,content_hash=x.content_hash)
  elif x.command=="fail": value=fail(x.root,x.item_id,claim_token=x.token)
  else: value={"recovered_item_ids":recover(x.root)}
  sys.stdout.write(serialize_report(value)); return 0
 except (OSError,ValueError,json.JSONDecodeError) as exc: print(f"SCAN: outbox error: {exc}",file=sys.stderr); return 1
