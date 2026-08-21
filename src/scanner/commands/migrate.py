"""Safe auditable local contract migration CLI."""
from __future__ import annotations
import argparse,json,os,tempfile
from pathlib import Path
import sys
from collections.abc import Mapping,Sequence
from scanner.contract import canonical_json,semantic_hash
from scanner.contract_registry import detect_contract
from scanner.loaders import load_json_document
from scanner.migration_registry import migrate_document,RULE_VERSION
from scanner.report import utc_timestamp
def _create_json(path: Path,value: Mapping) -> None:
    path=Path(path)
    if path.exists(): raise FileExistsError("destination already exists")
    path.parent.mkdir(parents=True,exist_ok=True); temporary=None
    try:
        with tempfile.NamedTemporaryFile("w",encoding="utf-8",dir=path.parent,prefix=f".{path.name}.",suffix=".tmp",delete=False) as h:
            temporary=Path(h.name); json.dump(value,h,indent=2,ensure_ascii=False); h.write("\n"); h.flush(); os.fsync(h.fileno())
        os.link(temporary,path); temporary.unlink(); temporary=None
    finally:
        if temporary is not None: temporary.unlink(missing_ok=True)
def migrate_main(argv: Sequence[str]) -> int:
    p=argparse.ArgumentParser(prog="SCAN migrate"); p.add_argument("input",type=Path); p.add_argument("--to",required=True); p.add_argument("--output",type=Path,required=True); p.add_argument("--receipt",type=Path); a=p.parse_args(argv)
    try:
        if a.input.resolve()==a.output.resolve(): raise ValueError("input and output must differ")
        destination_type,destination_version=a.to.split(":",1); source=load_json_document(a.input); source_type,source_version=detect_contract(source); migrated,rule=migrate_document(source,source_type,source_version,destination_type,destination_version)
        receipt={"migration_receipt_version":"1.0","document_type":"scan_migration_receipt","source":{"type":source_type,"version":source_version,"content_hash":semantic_hash(source)},"destination":{"type":destination_type,"version":destination_version,"content_hash":semantic_hash(migrated)},"migration_rule":{"id":rule,"version":RULE_VERSION},"lossy":False,"limitations":["migration_does_not_create_evidence"],"fields_synthesized_as_not_recorded":["execution_policy","acquisition_segments"],"migrated_at":utc_timestamp()}
        _create_json(a.output,migrated)
        if a.receipt:
            try: _create_json(a.receipt,receipt)
            except Exception: a.output.unlink(missing_ok=True); raise
        else: sys.stdout.write(json.dumps(receipt,indent=2)+"\n")
        return 0
    except (OSError,ValueError,json.JSONDecodeError) as exc: print(f"SCAN: migration error: {exc}",file=sys.stderr); return 1
