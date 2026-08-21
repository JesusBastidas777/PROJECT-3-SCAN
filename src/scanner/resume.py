"""Explicit fail-closed checkpoint resume compatibility checks."""
from __future__ import annotations
from collections.abc import Mapping
def validate_resume(checkpoint: Mapping,*,target_id: str,measurement_scope_fingerprint: str,execution_policy_fingerprint: str) -> None:
    if checkpoint.get("target",{}).get("target_id")!=target_id: raise ValueError("checkpoint target is incompatible")
    if checkpoint.get("measurement_scope_fingerprint")!=measurement_scope_fingerprint: raise ValueError("checkpoint measurement scope is incompatible")
    if checkpoint.get("execution_policy_fingerprint")!=execution_policy_fingerprint: raise ValueError("checkpoint execution policy is incompatible")
def acquisition_provenance(*,started_at: str,completed_at: str,resumed_from: str|None=None,previous_segments: list|None=None) -> dict:
    segment={"acquisition_segment_id":"segment_"+completed_at.replace(":","").replace("-","").replace(".",""),"started_at":started_at,"completed_at":completed_at,"source":"fresh"}
    segments=list(previous_segments or [])+[segment]
    return {"mode":"resumed" if resumed_from else "single_segment","segments":segments,"temporal_span_ms":None if len(segments)>1 else 0,"temporally_uniform":not bool(resumed_from),"resumed_from_checkpoint_id":resumed_from,"limitations":["resumed_evidence_was_not_captured_simultaneously"] if resumed_from else []}
