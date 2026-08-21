"""Bounded operational projection for FOREX and its GUI."""
from __future__ import annotations

from typing import Any, Mapping

from scanner.findings import findings_from_report


def build_operational_view(
    report: Mapping[str, Any], *, runtime_status: Mapping[str, Any] | None = None,
    references: Mapping[str, Any] | None = None, outbox_state: Mapping[str, int] | None = None,
    comparison: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    observations = list(report.get("observations", []))
    states = {state: sum(item.get("state") == state for item in observations) for state in ("open", "closed", "unknown", "error")}
    service_hints = sum(bool(item.get("service_hint")) for item in observations)
    findings = findings_from_report(report)
    coverage = report.get("coverage", {})
    phases = coverage.get("phases", {}) if isinstance(coverage, Mapping) else {}
    coverage_summary = {
        name: {
            "status": phase.get("status"), "counts": dict(phase.get("counts", {})),
            "complete_within_configured_scope": phase.get("complete_within_configured_scope"),
        }
        for name, phase in sorted(phases.items())
    }
    acquisition = report.get("acquisition", {})
    segments = acquisition.get("segments", []) if isinstance(acquisition, Mapping) else []
    comparison_summary = None
    if comparison:
        comparison_summary = {
            "comparison_id": comparison.get("comparison_id"),
            "comparability": comparison.get("comparability"),
            "changes": len(comparison.get("changes", [])),
            "indeterminate": len(comparison.get("indeterminate", [])),
        }
    target = report.get("target", {})
    value = {
        "operational_view_schema_version": "1.0", "document_type": "scan_operational_view",
        "runtime_state": (runtime_status or {}).get("lifecycle", "unavailable"),
        "job_state": (runtime_status or {}).get("job_state"),
        "target": {key: target.get(key) for key in ("input", "network", "target_id", "ip_version")},
        "scan_id": report.get("scan_id"), "started_at": report.get("started_at"),
        "completed_at": report.get("completed_at"), "duration_ms": report.get("duration_ms"),
        "partial": bool(report.get("partial")), "resumed": bool(acquisition.get("resumed_from")) or len(segments) > 1,
        "counts": {"assets": len(report.get("assets", [])), "endpoints": len(observations), **states,
                   "service_hints": service_hints, "findings": len(findings), "errors": len(report.get("errors", []))},
        "coverage_summary": coverage_summary, "capabilities": dict(report.get("capabilities", {})),
        "baseline_comparison": comparison_summary, "references": dict(references or {}),
        "outbox_state": dict(outbox_state or {state: 0 for state in ("pending", "processing", "acknowledged", "failed")}),
        "baseline_eligible": bool(report.get("baseline_eligible", False)),
    }
    validate_operational_view(value)
    return value


def validate_operational_view(value: Mapping[str, Any]) -> None:
    required = {"operational_view_schema_version", "document_type", "runtime_state", "job_state", "target", "scan_id", "started_at", "completed_at", "duration_ms", "partial", "resumed", "counts", "coverage_summary", "capabilities", "baseline_comparison", "references", "outbox_state", "baseline_eligible"}
    if required - value.keys() or value.get("operational_view_schema_version") != "1.0" or value.get("document_type") != "scan_operational_view":
        raise ValueError("invalid SCAN operational view")
    if value.get("partial") or value.get("resumed"):
        if value.get("baseline_eligible"):
            raise ValueError("partial or resumed view cannot be baseline eligible")
