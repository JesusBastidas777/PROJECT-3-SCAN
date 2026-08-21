"""Crash-recoverable local FOREX outbox with at-least-once semantics."""
from __future__ import annotations
import secrets,time
from collections.abc import Mapping
from pathlib import Path
from scanner.contract import semantic_hash
from scanner.contract_registry import detect_contract,get_contract
from scanner.loaders import load_json_document
from scanner.locking import FileLock
from scanner.report import utc_timestamp,write_report_atomic
STATES=("pending","processing","acknowledged","failed")
def _root(root: Path) -> Path:
    supplied=Path(root)
    if supplied.is_symlink(): raise OSError("outbox root cannot be a symlink")
    value=supplied.resolve(); value.mkdir(parents=True,exist_ok=True)
    for state in STATES: (value/state).mkdir(exist_ok=True)
    (value/"locks").mkdir(exist_ok=True); return value
def build_item(payload: Mapping,*,privacy: str="hash-only") -> dict:
    type_name,version=detect_contract(payload); get_contract(type_name,version).validator(payload); content_hash=semantic_hash(payload); scan_id=str(payload.get("scan_id",payload.get("report",{}).get("scan_id","not_applicable"))); dedup="dedup_"+semantic_hash({"type":type_name,"scan_id":scan_id,"content_hash":content_hash})
    return {"outbox_schema_version":"1.0","document_type":"forex_outbox_item","item_id":"outbox_"+semantic_hash({"deduplication_key":dedup})[:24],"created_at":utc_timestamp(),"payload_type":type_name,"payload_schema_version":version,"scan_id":scan_id,"deduplication_key":dedup,"content_hash":content_hash,"privacy":privacy,"delivery_semantics":"at_least_once_idempotent_consumer","payload":dict(payload),"claim":None}
def validate_item(item: Mapping) -> None:
    required={"outbox_schema_version","document_type","item_id","created_at","payload_type","payload_schema_version","scan_id","deduplication_key","content_hash","privacy","delivery_semantics","payload","claim"}
    if required-item.keys() or item.get("outbox_schema_version")!="1.0" or item.get("delivery_semantics")!="at_least_once_idempotent_consumer" or semantic_hash(item["payload"])!=item.get("content_hash"): raise ValueError("invalid outbox item")
    get_contract(str(item["payload_type"]),str(item["payload_schema_version"])).validator(item["payload"])
def enqueue(root: Path,payload: Mapping,*,privacy: str="hash-only") -> dict:
    root=_root(root); item=build_item(payload,privacy=privacy); path=root/"pending"/(item["item_id"]+".json")
    with FileLock(root/"locks"/"outbox.lock"):
        if any((root/state/path.name).exists() for state in STATES): raise FileExistsError("duplicate outbox item")
        write_report_atomic(item,path)
    return item
def list_items(root: Path,*,state: str="pending",limit: int=100,offset: int=0) -> list[dict]:
    if state not in STATES or limit<1 or limit>1000 or offset<0: raise ValueError("invalid outbox listing")
    root=_root(root); paths=sorted((root/state).glob("outbox_*.json"))[offset:offset+limit]; return [load_json_document(path) for path in paths]
def show(root: Path,item_id: str) -> tuple[str,dict]:
    root=_root(root)
    if not item_id.startswith("outbox_") or not item_id.replace("_","").isalnum(): raise ValueError("invalid item id")
    for state in STATES:
        path=root/state/(item_id+".json")
        if path.exists(): value=load_json_document(path); validate_item(value); return state,value
    raise FileNotFoundError("outbox item not found")
def claim(root: Path,item_id: str,*,consumer_id: str,lease_seconds: float=60.0) -> dict:
    root=_root(root); token=secrets.token_hex(16)
    with FileLock(root/"locks"/"outbox.lock"):
        source=root/"pending"/(item_id+".json"); item=load_json_document(source); validate_item(item); item["claim"]={"consumer_id":consumer_id,"claim_token":token,"claimed_at":utc_timestamp(),"lease_deadline_unix":time.time()+lease_seconds}; temporary=root/"processing"/(item_id+".claim.json"); write_report_atomic(item,temporary); temporary.replace(root/"processing"/(item_id+".json")); source.unlink()
    return item
def acknowledge(root: Path,item_id: str,*,claim_token: str,content_hash: str) -> dict:
    root=_root(root)
    with FileLock(root/"locks"/"outbox.lock"):
        acknowledged=root/"acknowledged"/(item_id+".json")
        if acknowledged.exists():
            item=load_json_document(acknowledged)
            if item.get("content_hash")!=content_hash: raise ValueError("ACK content hash mismatch")
            return item
        source=root/"processing"/(item_id+".json"); item=load_json_document(source); validate_item(item)
        if item.get("claim",{}).get("claim_token")!=claim_token or item["content_hash"]!=content_hash: raise ValueError("invalid ACK token or content hash")
        source.replace(acknowledged); return item
def fail(root: Path,item_id: str,*,claim_token: str) -> dict:
    root=_root(root); source=root/"processing"/(item_id+".json"); item=load_json_document(source)
    if item.get("claim",{}).get("claim_token")!=claim_token: raise ValueError("invalid claim token")
    source.replace(root/"failed"/source.name); return item
def recover(root: Path,*,now: float|None=None) -> list[str]:
    root=_root(root); current=time.time() if now is None else now; recovered=[]
    with FileLock(root/"locks"/"outbox.lock"):
        for source in sorted((root/"processing").glob("outbox_*.json")):
            item=load_json_document(source)
            if float(item.get("claim",{}).get("lease_deadline_unix",0))<=current: item["claim"]=None; target=root/"pending"/source.name; write_report_atomic(item,target); source.unlink(); recovered.append(str(item["item_id"]))
    return recovered
