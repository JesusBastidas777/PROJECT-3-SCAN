"""Separate atomic checkpoint contract and storage namespace."""
from __future__ import annotations
from collections.abc import Mapping,Sequence
from pathlib import Path
from scanner.contract import semantic_hash
from scanner.loaders import load_json_document
from scanner.locking import FileLock
from scanner.report import utc_timestamp,write_report_atomic
def stable_work_unit_id(value: Mapping) -> str: return "work_"+semantic_hash(dict(value))[:24]
def build_checkpoint(*,target: Mapping,measurement_scope_fingerprint: str,execution_policy_fingerprint: str,configuration: Mapping,completed: Sequence[Mapping],pending: Sequence[Mapping],evidence: Sequence[Mapping],privacy: str,generation: int=1,created_at: str|None=None) -> dict:
    now=utc_timestamp(); material={"target":target,"measurement":measurement_scope_fingerprint,"configuration":configuration}; checkpoint_id="checkpoint_"+semantic_hash(material)[:24]
    return {"checkpoint_schema_version":"1.0","document_type":"scan_checkpoint","checkpoint_id":checkpoint_id,"target":dict(target),"measurement_scope_fingerprint":measurement_scope_fingerprint,"execution_policy_fingerprint":execution_policy_fingerprint,"configuration":dict(configuration),"completed_work_units":[dict(x) for x in completed],"pending_work_units":[dict(x) for x in pending],"evidence":[dict(x) for x in evidence],"created_at":created_at or now,"updated_at":now,"generation":generation,"provenance":{"producer":"SCAN","kind":"operational_checkpoint_not_snapshot"},"privacy":privacy}
def validate_checkpoint(value: Mapping) -> None:
    required={"checkpoint_schema_version","document_type","checkpoint_id","target","measurement_scope_fingerprint","execution_policy_fingerprint","configuration","completed_work_units","pending_work_units","evidence","created_at","updated_at","generation","provenance","privacy"}
    if required-value.keys() or value.get("checkpoint_schema_version")!="1.0" or value.get("document_type")!="scan_checkpoint" or not str(value.get("checkpoint_id","")).startswith("checkpoint_"): raise ValueError("invalid checkpoint 1.0")
    ids=[item.get("work_unit_id") for item in list(value["completed_work_units"])+list(value["pending_work_units"])]
    if any(not isinstance(x,str) for x in ids) or len(ids)!=len(set(ids)): raise ValueError("duplicate or invalid checkpoint work unit")
def save_checkpoint(value: Mapping,root: Path,*,lock_timeout: float=5.0) -> Path:
    validate_checkpoint(value); supplied=Path(root)
    if supplied.is_symlink(): raise OSError("checkpoint root cannot be a symlink")
    root=supplied.resolve(); root.mkdir(parents=True,exist_ok=True); path=root/(str(value["checkpoint_id"])+".json")
    with FileLock(root/".scan-checkpoint.lock",timeout=lock_timeout): write_report_atomic(value,path)
    return path
def load_checkpoint(path: Path,*,max_bytes: int=16*1024*1024) -> dict:
    value=load_json_document(path,max_bytes=max_bytes); validate_checkpoint(value); return value
