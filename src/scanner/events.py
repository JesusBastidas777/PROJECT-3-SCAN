"""Versioned, bounded and idempotent FOREX event envelopes."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from scanner.contract import semantic_hash
from scanner.findings import findings_from_report

EVENT_SCHEMA_VERSION = "1.0"
MAX_EVENT_BYTES = 16384


def _event(event_type: str, report: Mapping[str, Any], subject: Mapping[str, Any], observation: Mapping[str, Any], evidence_refs: Sequence[str] = (), limitations: Sequence[str] = ()) -> dict[str, Any]:
    semantic = {"event_type": event_type, "target_id": report["target"]["target_id"], "subject": subject, "observation": observation}
    deduplication_key = "dedup_" + semantic_hash(semantic)
    return {
        "event_schema_version": EVENT_SCHEMA_VERSION,
        "event_id": "event_" + semantic_hash({"scan_id": report["scan_id"], "deduplication_key": deduplication_key})[:24],
        "event_type": event_type, "occurred_at": report["completed_at"],
        "producer": {"name": "SCAN", "version": report["scanner"]["version"]},
        "scan_id": report["scan_id"], "target_id": report["target"]["target_id"],
        "subject": dict(subject), "observation": dict(observation),
        "evidence_refs": list(evidence_refs), "confidence": "observed",
        "limitations": list(limitations), "deduplication_key": deduplication_key,
    }


def events_from_report(report: Mapping[str, Any], *, max_events: int = 256) -> list[dict[str, Any]]:
    if report.get("schema_version") != "2.0" or max_events < 1:
        raise ValueError("events require schema 2.0 and a positive limit")
    candidates = []
    candidates.append(_event("scan.completed", report, {"target_id": report["target"]["target_id"]}, {"summary": report["summary"]}))
    for asset in report["assets"]:
        candidates.append(_event("asset.observed", report, {"asset_id": asset["asset_id"]}, {"addresses": asset["addresses"]}, limitations=["asset_id_is_not_a_physical_device_identity"]))
    findings = findings_from_report(report)
    for finding in findings:
        event_type = "probe.error" if finding["statement"] == "Probe was inconclusive." else "endpoint.observed"
        candidates.append(_event(event_type, report, {"asset_id": finding["asset_id"], "endpoint": finding["endpoint"]}, {"statement": finding["statement"]}, finding["evidence_refs"], ["evidence_does_not_imply_vulnerability"]))
    candidates.sort(key=lambda value: (value["event_type"], value["deduplication_key"]))
    if len(candidates) <= max_events:
        return candidates
    retained = candidates[:max_events - 1]
    retained.append(_event("scan.partial", report, {"target_id": report["target"]["target_id"]}, {"reason": "event_limit", "events_omitted": len(candidates) - len(retained)}, limitations=["event_output_truncated_explicitly"]))
    return retained


def validate_event(event: Mapping[str, Any]) -> None:
    required = {"event_schema_version", "event_id", "event_type", "occurred_at", "producer", "scan_id", "target_id", "subject", "observation", "evidence_refs", "confidence", "limitations", "deduplication_key"}
    if event.get("event_schema_version") != EVENT_SCHEMA_VERSION or required - event.keys():
        raise ValueError("invalid FOREX event")
    if len(str(event).encode("utf-8")) > MAX_EVENT_BYTES:
        raise ValueError("FOREX event exceeds payload limit")
