"""Bounded offline contract validation returning machine-safe diagnostics."""
from __future__ import annotations
import json
from pathlib import Path
from scanner.contract_registry import detect_contract,get_contract
from scanner.loaders import load_json_document
def validate_file(path: Path,*,type_name: str|None=None,version: str|None=None,max_bytes: int=16*1024*1024,strict: bool=False) -> dict:
    result={"validation_result_version":"1.0","document_type":"scan_validation_result","valid":False,"input":{"path":str(path),"max_bytes":max_bytes},"detected":None,"errors":[],"meaning":"contract_conformance_only_not_evidence_truth"}
    try:
        value=load_json_document(path,max_bytes=max_bytes); detected_type,detected_version=detect_contract(value); chosen_type=type_name or detected_type; chosen_version=version or detected_version
        if type_name and type_name!=detected_type: raise ValueError("structural_error")
        spec=get_contract(chosen_type,chosen_version); spec.validator(value); result["detected"]={"type":detected_type,"version":detected_version}; result["valid"]=True
    except OSError as exc: result["errors"].append({"code":"oversized_input" if "size limit" in str(exc) else "io_error","path":"$","message":str(exc)})
    except json.JSONDecodeError: result["errors"].append({"code":"parse_error","path":"$","message":"invalid JSON"})
    except (ValueError,TypeError,KeyError) as exc:
        code=str(exc) if str(exc) in {"unknown_document_type","unsupported_version","structural_error"} else "invariant_error"; result["errors"].append({"code":code,"path":"$","message":str(exc)})
    return result
