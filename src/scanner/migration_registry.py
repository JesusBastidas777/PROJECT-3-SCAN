"""Explicit conservative contract migration matrix."""
from __future__ import annotations
from copy import deepcopy
from collections.abc import Callable,Mapping
from scanner.baselines import baseline_identity
from scanner.contract import semantic_hash,validate_report_shape
from scanner.coverage import coverage_v2
RULE_VERSION="1.0"
def report_21_to_22(source: Mapping) -> dict:
    validate_report_shape(source)
    if source.get("schema_version")!="2.1": raise ValueError("migration source mismatch")
    value=deepcopy(source); value["schema_version"]="2.2"; value["coverage"]=coverage_v2(value["coverage"]); value["partial"]=False; value["termination"]=None
    value["measurement_scope_fingerprint"]=baseline_identity(value)["measurement_scope_fingerprint"]; value["execution_policy_fingerprint"]=semantic_hash({"status":"not_recorded"}); value["acquisition"]={"mode":"not_recorded","segments":[],"temporal_span_ms":None,"temporally_uniform":False,"limitations":["source_contract_did_not_record_acquisition_segments"]}; value["baseline_eligible"]=False; value["migration"]={"rule_id":"report-2.1-to-2.2","rule_version":RULE_VERSION,"execution_policy":"not_recorded","acquisition_segments":"not_recorded","limitations":["migration_does_not_create_evidence"]}
    return value
MIGRATIONS={("report","2.1","report","2.2"):("report-2.1-to-2.2",report_21_to_22)}
def migrate_document(value: Mapping,source_type: str,source_version: str,destination_type: str,destination_version: str) -> tuple[dict,str]:
    try: rule,function=MIGRATIONS[(source_type,source_version,destination_type,destination_version)]
    except KeyError as exc: raise ValueError("unsupported migration") from exc
    return function(value),rule
