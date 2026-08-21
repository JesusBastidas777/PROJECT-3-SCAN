"""Deterministic local projections over validated SCAN evidence."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

QUERY_SCHEMA_VERSION = "1.0"
MAX_QUERY_RESULTS = 10000


def _v1_endpoints(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [{"asset_id":host["host"],"transport":"tcp","port":item["port"],"state":"open" if item["status"] == "OPEN" else "closed"} for host in report.get("hosts", []) for item in host.get("ports", [])]


def query_report(report: Mapping[str, Any], *, asset_id: str | None = None, open_endpoints: bool = False, errors: bool = False, coverage: bool = False, evidence_ref: str | None = None, max_results: int = MAX_QUERY_RESULTS) -> dict[str, Any]:
    if max_results < 1 or sum(bool(value) for value in (asset_id, open_endpoints, errors, coverage, evidence_ref)) > 1:
        raise ValueError("select exactly one valid bounded query")
    version = str(report.get("schema_version"))
    kind = "summary"; results: Any
    if asset_id:
        kind = "asset"
        if version == "1.0": results = [host for host in report.get("hosts", []) if host.get("host") == asset_id]
        else: results = [asset for asset in report.get("assets", []) if asset.get("asset_id") == asset_id]
    elif open_endpoints:
        kind = "open_endpoints"; items = _v1_endpoints(report) if version == "1.0" else list(report.get("observations", []))
        results = [item for item in items if item.get("state") == "open"]
    elif errors:
        kind = "errors"; results = list(report.get("errors", [])) if version != "1.0" else ([{"code":"legacy_errors_present","count":report.get("summary", {}).get("total_errors", 0)}] if report.get("summary", {}).get("total_errors") else [])
    elif coverage:
        kind = "coverage"; results = report.get("coverage") if version == "2.1" else {"status":"unavailable","reason":"report_version_has_no_coverage"}
    elif evidence_ref:
        kind = "evidence_ref"; collections = [report.get("observations", []), report.get("discovery_observations", []), report.get("neighbor_observations", []), report.get("evidence_clusters", [])]
        id_fields = ("observation_id","discovery_observation_id","neighbor_observation_id","relation_id")
        results = [item for values in collections for item in values if any(item.get(field) == evidence_ref for field in id_fields)]
    else:
        results = report.get("summary", {})
    if isinstance(results, list):
        ordered = sorted(results, key=lambda item: tuple(str(item.get(key, "")) for key in ("asset_id","observation_id","port","code","relation_id")))
        omitted = max(0, len(ordered) - max_results); results = ordered[:max_results]
    else:
        omitted = 0
    return {"query_schema_version":QUERY_SCHEMA_VERSION,"document_type":"scan_evidence_query","report_schema_version":version,"query":kind,"count":len(results) if isinstance(results,list) else 1,"truncated":omitted>0,"omitted":omitted,"results":results}
