"""Deterministic, bounded candidate correlation over report evidence."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from typing import Any

from scanner.contract import semantic_hash
from scanner.correlation_rules import RELATION_LIMITATIONS, RULESET_VERSION, SIGNAL_CLASS


def _address_assets(report: Mapping[str, Any]) -> dict[str, str]:
    return {str(address["address"]): str(asset["asset_id"]) for asset in report.get("assets", []) for address in asset.get("addresses", [])}


def _signals(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    for item in report.get("observations", []):
        asset = str(item.get("asset_id")); reference = str(item.get("observation_id"))
        tls_hash = item.get("tls", {}).get("certificate_sha256")
        if tls_hash:
            signals.append({"type":"tls_certificate_sha256","value":str(tls_hash),"asset_id":asset,"evidence_ref":reference,"context":"scan"})
        http_hash = item.get("http", {}).get("body_prefix_sha256")
        if http_hash:
            signals.append({"type":"http_body_prefix_sha256","value":str(http_hash),"asset_id":asset,"evidence_ref":reference,"context":"scan"})
    by_address = _address_assets(report)
    for item in report.get("neighbor_observations", []):
        asset = by_address.get(str(item.get("address")))
        link_hash = item.get("link_layer_sha256")
        if asset and link_hash:
            context = f"{item.get('network_context')}:{item.get('interface')}"
            signals.append({"type":"neighbor_link_layer_sha256","value":str(link_hash),"asset_id":asset,"evidence_ref":str(item.get("neighbor_observation_id")),"context":context})
    signals.sort(key=lambda item: (item["type"], item["value"], item["context"], item["asset_id"], item["evidence_ref"]))
    return signals


def correlate_report(report: Mapping[str, Any], *, max_signals: int = 4096, max_relations: int = 256) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Return explainable candidate clusters without mutating or merging assets."""
    if max_signals < 1 or max_relations < 1:
        raise ValueError("correlation limits must be positive")
    all_signals = _signals(report)
    selected = all_signals[:max_signals]
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for signal in selected:
        groups[(signal["type"], signal["value"], signal["context"])].append(signal)
    candidates = []
    for (signal_type, value, context), members in sorted(groups.items()):
        assets = sorted({item["asset_id"] for item in members})
        if len(assets) < 2 or SIGNAL_CLASS[signal_type] == "weak":
            continue
        evidence_refs = sorted({item["evidence_ref"] for item in members})
        material = {"type": signal_type, "value": value, "context": context, "assets": assets}
        candidates.append({
            "relation_id": "relation_" + semantic_hash(material)[:24],
            "relation_type": "candidate_shared_endpoint_identity",
            "members": assets, "evidence_refs": evidence_refs,
            "confidence": "medium" if SIGNAL_CLASS[signal_type] == "strong_for_relation" else "low",
            "basis": [{"signal_type": signal_type, "classification": SIGNAL_CLASS[signal_type], "value_sha256": semantic_hash(value), "context": context}],
            "limitations": list(RELATION_LIMITATIONS), "scope": str(report.get("scan_id")),
            "ruleset_version": RULESET_VERSION, "contradictions": [],
            "physical_device_asserted": False,
        })
    neighbor_by_asset: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for signal in selected:
        if signal["type"] == "neighbor_link_layer_sha256":
            neighbor_by_asset[signal["asset_id"]].add((signal["context"], signal["value"]))
    for relation in candidates:
        common_contexts = set.intersection(*[{context for context, _ in neighbor_by_asset.get(asset, set())} for asset in relation["members"]]) if all(neighbor_by_asset.get(asset) for asset in relation["members"]) else set()
        for context in sorted(common_contexts):
            hashes = {value for asset in relation["members"] for candidate_context, value in neighbor_by_asset[asset] if candidate_context == context}
            if len(hashes) > 1:
                relation["contradictions"].append({"type":"different_neighbor_link_layer_hash","context":context,"meaning":"relation_remains_candidate"})
    candidates.sort(key=lambda item: item["relation_id"])
    retained = candidates[:max_relations]
    return retained, {
        "ruleset_version": RULESET_VERSION, "signals_eligible": len(all_signals), "signals_processed": len(selected),
        "relations_eligible": len(candidates), "relations_observed": len(retained),
        "truncated": len(selected) < len(all_signals) or len(retained) < len(candidates),
        "omitted_signals": len(all_signals) - len(selected), "omitted_relations": len(candidates) - len(retained),
    }
