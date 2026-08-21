"""Explicit strict and measured-common-scope comparison policies."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from scanner.baselines import baseline_identity
from scanner.changes import compare_snapshots


def _phase_comparability(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, Any]:
    left = before.get("coverage", {}).get("phases", {})
    right = after.get("coverage", {}).get("phases", {})
    names = sorted(set(left) | set(right))
    output = {}
    for name in names:
        a, b = left.get(name), right.get(name)
        reasons = []
        if a is None or b is None: reasons.append("phase_missing")
        elif a.get("enabled") != b.get("enabled"): reasons.append("enabled_changed")
        elif a.get("effective_limits") != b.get("effective_limits"): reasons.append("limits_changed")
        if a and (a.get("truncated") or not a.get("complete_within_configured_scope")): reasons.append("baseline_coverage_partial")
        if b and (b.get("truncated") or not b.get("complete_within_configured_scope")): reasons.append("current_coverage_partial")
        output[name] = {
            "target_equivalent": before.get("target", {}).get("target_id") == after.get("target", {}).get("target_id"),
            "scope_intersection": bool(a is not None and b is not None),
            "coverage_sufficient": not any("coverage_partial" in reason for reason in reasons),
            "configuration_equivalent": not any(reason in {"enabled_changed", "limits_changed"} for reason in reasons),
            "reason_codes": reasons,
        }
    return output


def build_comparison_v2(baseline: Mapping[str, Any], current: Mapping[str, Any], *, policy: str = "strict", explain: bool = False) -> dict[str, Any]:
    if policy not in {"strict", "common-scope"}:
        raise ValueError("invalid comparison policy")
    before, after = baseline["report"], current["report"]
    if before.get("target", {}).get("target_id") != after.get("target", {}).get("target_id"):
        raise ValueError("snapshots have different target scopes")
    left_identity, right_identity = baseline_identity(before), baseline_identity(after)
    exact = left_identity["measurement_scope_fingerprint"] == right_identity["measurement_scope_fingerprint"]
    legacy = compare_snapshots(baseline, current)
    phase_details = _phase_comparability(before, after)
    if exact:
        status = "comparable"
    elif policy == "common-scope" and legacy["comparison_scope"]["common_ports"]:
        status = "partially_comparable"
    else:
        status = "incomparable"
    changes = legacy["changes"] if status != "incomparable" else []
    indeterminate = list(legacy["indeterminate"])
    if status == "incomparable":
        indeterminate.append({"reason":"measurement_scope_mismatch","limitation":"configuration_change_is_not_network_change"})
    result = {
        "comparison_schema_version": "2.0", "document_type": "snapshot_comparison",
        "baseline_snapshot_id": baseline["snapshot_id"], "current_snapshot_id": current["snapshot_id"],
        "policy": policy, "comparability": status,
        "baseline_identity": {key:value for key,value in left_identity.items() if key != "measurement_scope"},
        "current_identity": {key:value for key,value in right_identity.items() if key != "measurement_scope"},
        "comparison_scope": legacy["comparison_scope"],
        "changes_summary": {"total":len(changes),"indeterminate":len(indeterminate)},
        "changes": changes, "indeterminate": indeterminate,
    }
    if explain:
        result["phase_comparability"] = phase_details
    return result


def validate_comparison_v2(value: Mapping[str, Any]) -> None:
    required = {"comparison_schema_version","document_type","baseline_snapshot_id","current_snapshot_id","policy","comparability","baseline_identity","current_identity","comparison_scope","changes_summary","changes","indeterminate"}
    if required - value.keys() or value.get("comparison_schema_version") != "2.0" or value.get("comparability") not in {"comparable","partially_comparable","incomparable"}:
        raise ValueError("invalid comparison 2.0")
    if value["changes_summary"] != {"total":len(value["changes"]),"indeterminate":len(value["indeterminate"])}:
        raise ValueError("comparison 2.0 summary mismatch")
