"""Small factual findings derived without risk or vulnerability claims."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def findings_from_report(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    findings = []
    for item in report.get("observations", []):
        state = item.get("state")
        if state == "open":
            text, confidence = "TCP endpoint accepted a connection.", "observed"
        elif state in {"unknown", "error"}:
            text, confidence = "Probe was inconclusive.", "observed"
        else:
            continue
        findings.append({"finding_type": "endpoint_observation", "asset_id": item["asset_id"], "endpoint": {"transport": item.get("transport", "tcp"), "port": item["port"]}, "statement": text, "confidence": confidence, "evidence_refs": [item["observation_id"]]})
    return sorted(findings, key=lambda value: (value["asset_id"], value["endpoint"]["transport"], value["endpoint"]["port"], value["statement"]))


def findings_from_changes(comparison: Mapping[str, Any]) -> list[dict[str, Any]]:
    findings = []
    statements = {"endpoint_state_changed": "Endpoint state changed between comparable observations.", "endpoint_newly_observed": "New endpoint observed in this target.", "banner_changed": "Banner content changed."}
    for change in comparison.get("changes", []):
        findings.append({"finding_type": "network_change", "asset_id": change["asset_id"], "endpoint": change["endpoint"], "statement": statements[change["change_type"]], "confidence": change["confidence"], "limitations": change.get("limitations", [])})
    return findings
