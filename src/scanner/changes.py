"""Semantically conservative comparison of schema-2.0 snapshots."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def _endpoint_index(report: Mapping[str, Any]) -> dict[tuple[str, str, int], Mapping[str, Any]]:
    return {(str(item["asset_id"]), str(item.get("transport", "tcp")), int(item["port"])): item for item in report["observations"]}


def compare_snapshots(baseline: Mapping[str, Any], current: Mapping[str, Any]) -> dict[str, Any]:
    """Compare only actually measured common scope; absence stays indeterminate."""

    before = baseline["report"]
    after = current["report"]
    if before["target"]["target_id"] != after["target"]["target_id"]:
        raise ValueError("snapshots have different target scopes")
    configuration_match = baseline["configuration_fingerprint"] == current["configuration_fingerprint"]
    before_ports = set(before["configuration"]["ports"])
    after_ports = set(after["configuration"]["ports"])
    common_ports = sorted(before_ports & after_ports)
    left = _endpoint_index(before)
    right = _endpoint_index(after)
    changes: list[dict[str, Any]] = []
    indeterminate: list[dict[str, Any]] = []
    for key in sorted(set(left) | set(right)):
        asset, transport, port = key
        endpoint = {"transport": transport, "port": port}
        old, new = left.get(key), right.get(key)
        if old is None:
            if port in common_ports:
                changes.append({"change_type": "endpoint_newly_observed", "asset_id": asset, "endpoint": endpoint, "after": {"state": new["state"]}, "confidence": "observed", "comparable": True})
            else:
                indeterminate.append({"reason": "endpoint_not_in_common_scope", "asset_id": asset, "endpoint": endpoint})
            continue
        if new is None:
            indeterminate.append({"reason": "endpoint_not_observed", "asset_id": asset, "endpoint": endpoint, "limitation": "absence_does_not_mean_host_offline"})
            continue
        old_state, new_state = old.get("state"), new.get("state")
        if old_state != new_state:
            if old_state in {"open", "closed"} and new_state in {"open", "closed"}:
                changes.append({"change_type": "endpoint_state_changed", "asset_id": asset, "endpoint": endpoint, "before": {"state": old_state}, "after": {"state": new_state}, "confidence": "observed", "comparable": True})
            else:
                indeterminate.append({"reason": "inconclusive_state_transition", "asset_id": asset, "endpoint": endpoint, "before": {"state": old_state}, "after": {"state": new_state}})
        old_banner, new_banner = old.get("banner"), new.get("banner")
        if isinstance(old_banner, Mapping) and isinstance(new_banner, Mapping) and old_banner.get("sha256") and new_banner.get("sha256") and old_banner["sha256"] != new_banner["sha256"]:
            changes.append({"change_type": "banner_changed", "asset_id": asset, "endpoint": endpoint, "before": {"sha256": old_banner["sha256"]}, "after": {"sha256": new_banner["sha256"]}, "confidence": "observed", "comparable": True, "limitations": ["banner_change_does_not_confirm_software_change"]})
    changes.sort(key=lambda item: (item["change_type"], item["asset_id"], item["endpoint"]["transport"], item["endpoint"]["port"]))
    indeterminate.sort(key=lambda item: (item["reason"], item["asset_id"], item["endpoint"]["transport"], item["endpoint"]["port"]))
    return {
        "baseline_snapshot_id": baseline["snapshot_id"], "current_snapshot_id": current["snapshot_id"],
        "configuration_match": configuration_match,
        "comparison_scope": {"target_id": before["target"]["target_id"], "common_ports": common_ports, "transport": "tcp", "common_capabilities": sorted(key for key in set(before.get("capabilities", {})) & set(after.get("capabilities", {})) if before["capabilities"].get(key) and after["capabilities"].get(key))},
        "changes_summary": {"total": len(changes), "indeterminate": len(indeterminate)},
        "changes": changes, "indeterminate": indeterminate,
    }


def build_comparison(baseline: Mapping[str, Any], current: Mapping[str, Any]) -> dict[str, Any]:
    """Build a deterministic independently versioned comparison document."""
    return {"comparison_schema_version": "1.0", "document_type": "snapshot_comparison", **compare_snapshots(baseline, current)}


def validate_comparison(value: Mapping[str, Any]) -> None:
    required = {"comparison_schema_version", "document_type", "baseline_snapshot_id", "current_snapshot_id", "configuration_match", "comparison_scope", "changes_summary", "changes", "indeterminate"}
    if required - value.keys() or value.get("comparison_schema_version") != "1.0" or value.get("document_type") != "snapshot_comparison": raise ValueError("invalid comparison contract")
    if not isinstance(value["changes"], list) or not isinstance(value["indeterminate"], list): raise ValueError("invalid comparison collections")
    if value["changes_summary"].get("total") != len(value["changes"]) or value["changes_summary"].get("indeterminate") != len(value["indeterminate"]): raise ValueError("comparison summary mismatch")
