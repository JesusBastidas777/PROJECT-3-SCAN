"""Versioned report construction and semantic canonicalization."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from collections.abc import Mapping, Sequence
from typing import Any

from scanner.inventory import build_inventory, target_id
from scanner.discovery_evidence import discovery_summary

SUPPORTED_REPORT_VERSIONS = ("1.0", "2.0", "2.1")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def semantic_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def canonical_content(report: Mapping[str, Any]) -> dict[str, Any]:
    """Remove contract-defined volatile execution fields before content hashing."""

    excluded = {"scan_id", "started_at", "completed_at", "timestamp", "duration_ms", "snapshot_id", "previous_snapshot_id"}
    return {key: value for key, value in report.items() if key not in excluded}


def build_report_v2(*, target_input: str, network: object, host_results: Mapping[str, Sequence[Mapping[str, Any]]], ports: Sequence[int], started_at: str, completed_at: str, duration_ms: int, ping_timeout: float, connect_timeout: float, workers: int, max_hosts: int, banners_enabled: bool, banner_limits: Mapping[str, Any], discovery_observations: Sequence[Mapping[str, Any]] = (), discovery_configuration: Mapping[str, Any] | None = None, tls_configuration: Mapping[str, Any] | None = None, name_observations: Sequence[Mapping[str, Any]] = (), dns_configuration: Mapping[str, Any] | None = None, profile_configuration: Mapping[str, Any] | None = None) -> dict[str, Any]:
    network_obj = ipaddress.ip_network(str(network), strict=False)
    configuration = {
        "ports": sorted(set(ports)), "discovery": "icmp", "workers": workers,
        "max_hosts": max_hosts, "ping_timeout_seconds": ping_timeout,
        "connect_timeout_seconds": connect_timeout, "banners_enabled": banners_enabled,
        "banner_limits": dict(banner_limits) if banners_enabled else None,
    }
    if discovery_configuration:
        configuration["discovery_configuration"] = dict(discovery_configuration)
    if tls_configuration:
        configuration["tls"] = dict(tls_configuration)
    if dns_configuration:
        configuration["dns"] = dict(dns_configuration)
    if profile_configuration and profile_configuration.get("name"):
        configuration["profile"] = dict(profile_configuration)
    scan_material = {"target": str(network_obj), "started_at": started_at, "configuration": configuration}
    scan_id = "scan_" + semantic_hash(scan_material)[:24]
    assets = build_inventory(network_obj, host_results)
    observations = []
    errors = []
    for asset in assets:
        for endpoint in asset["endpoints"]:
            item = dict(endpoint)
            item.update({"observation_id": "obs_" + semantic_hash({"asset_id": asset["asset_id"], "endpoint": endpoint})[:24], "asset_id": asset["asset_id"]})
            observations.append(item)
            if endpoint.get("state") == "error":
                errors.append({"code": endpoint.get("error", {}).get("code", "probe_error"), "observation_id": item["observation_id"]})
    state_counts = {state: sum(item.get("state") == state for item in observations) for state in ("open", "closed", "unknown", "error")}
    return {
        "schema_version": "2.0", "document_type": "scan_report", "scan_id": scan_id,
        "scanner": {"name": "SCAN", "version": "2.0.0"},
        "started_at": started_at, "completed_at": completed_at, "duration_ms": duration_ms,
        "target": {"input": target_input, "network": str(network_obj), "target_id": target_id(network_obj), "ip_version": network_obj.version},
        "configuration": configuration,
        "effective_configuration": dict(configuration),
        "capabilities": {"tcp_connect": True, "ipv4": True, "ipv6": True, "service_hints": True, "passive_banners": any("banner" in item for values in host_results.values() for item in values), "tls_handshake": any("tls" in item for values in host_results.values() for item in values), "reverse_dns": any(item.get("status") != "skipped" for item in name_observations), "fingerprints": True, "inventory": True},
        "summary": {"assets_observed": len(assets), "observations": len(observations), "states": state_counts, "errors": len(errors), "discovery": discovery_summary(list(discovery_observations))},
        "assets": assets, "observations": observations, "errors": errors,
        "discovery_observations": [dict(item) for item in discovery_observations],
        "name_observations": [dict(item) for item in name_observations],
    }


def build_report_v21(**arguments: Any) -> dict[str, Any]:
    """Build report 2.1 while leaving the report-2.0 builder frozen."""

    from scanner.coverage import build_coverage

    neighbor_observations = list(arguments.pop("neighbor_observations", ()))
    neighbor_execution = dict(arguments.pop("neighbor_execution", {}))
    neighbor_configuration = dict(arguments.pop("neighbor_configuration", {}))
    http_configuration = dict(arguments.pop("http_configuration", {}))
    report = build_report_v2(**arguments)
    report["configuration"]["neighbors"] = neighbor_configuration
    report["configuration"]["http"] = http_configuration
    report["effective_configuration"] = dict(report["configuration"])
    report["schema_version"] = "2.1"
    report["scanner"] = {"name": "SCAN", "version": "2.1.0"}
    report["coverage"] = build_coverage(
        observations=report["observations"],
        discovery_observations=report.get("discovery_observations", []),
        name_observations=report.get("name_observations", []),
        configuration=report["configuration"],
        neighbor_observations=neighbor_observations,
        neighbor_execution=neighbor_execution,
    )
    report["capability_execution"] = {
        name: {
            "support": phase["support"], "backend": phase["backend"],
            "enabled": phase["enabled"], "complete_within_configured_scope": phase["complete_within_configured_scope"],
        }
        for name, phase in report["coverage"]["phases"].items()
    }
    report["neighbor_observations"] = neighbor_observations
    return report


def validate_report_shape(report: Mapping[str, Any]) -> None:
    version = report.get("schema_version")
    if version not in SUPPORTED_REPORT_VERSIONS:
        raise ValueError("unsupported report schema version")
    required = {"schema_version", "scanner", "target", "summary"}
    if version == "1.0":
        required |= {"network", "timestamp", "duration_ms", "hosts", "metadata"}
    else:
        required |= {"document_type", "scan_id", "started_at", "completed_at", "duration_ms", "configuration", "capabilities", "assets", "observations", "errors"}
        if report.get("document_type") != "scan_report":
            raise ValueError("invalid document_type")
    missing = required - report.keys()
    if missing:
        raise ValueError(f"missing required report fields: {sorted(missing)}")
    if not isinstance(report.get("scanner"), Mapping) or not isinstance(report.get("summary"), Mapping) or not isinstance(report.get("target"), Mapping):
        raise ValueError("invalid report object fields")
    if version == "1.0":
        if not isinstance(report["hosts"], list) or not isinstance(report["metadata"], Mapping): raise ValueError("invalid schema-1.0 collections")
        return
    for field in ("assets", "observations", "errors"):
        if not isinstance(report[field], list): raise ValueError(f"invalid {field}")
    observation_ids = [item.get("observation_id") for item in report["observations"]]
    if any(not isinstance(value, str) for value in observation_ids) or len(observation_ids) != len(set(observation_ids)): raise ValueError("observation IDs must be unique strings")
    asset_ids = {item.get("asset_id") for item in report["assets"]}
    if any(item.get("asset_id") not in asset_ids for item in report["observations"]): raise ValueError("observation references unknown asset")
    states = {state: sum(item.get("state") == state for item in report["observations"]) for state in ("open", "closed", "unknown", "error")}
    if report["summary"].get("states") != states or report["summary"].get("observations") != len(report["observations"]): raise ValueError("report summary does not match observations")
    if version == "2.1":
        from scanner.coverage import validate_coverage
        if not isinstance(report.get("capability_execution"), Mapping): raise ValueError("missing capability execution")
        validate_coverage(report.get("coverage", {}))
