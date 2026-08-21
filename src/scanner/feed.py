"""Compact, bounded and versioned SCAN sensor feed projection."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from scanner.baselines import baseline_identity
from scanner.contract import canonical_content, canonical_json, semantic_hash, validate_report_shape

FEED_SCHEMA_VERSION = "1.0"


def _address(value: str, privacy: str) -> dict[str, str]:
    return {"address":value} if privacy == "full" else {"address_sha256":hashlib.sha256(value.encode("utf-8")).hexdigest()}


def _coverage_summary(report: Mapping[str, Any]) -> dict[str, Any]:
    phases = report.get("coverage", {}).get("phases", {})
    if report.get("coverage",{}).get("model_version")=="2.0":
        return {name:{"status":phase.get("status"),**{key:phase.get("counts",{}).get(key) for key in ("completed","observed","timeout","error","not_started")},"complete_within_configured_scope":phase.get("complete_within_configured_scope")} for name,phase in phases.items()}
    return {name:{key:phase.get(key) for key in ("enabled","attempted","observed","timeout","error","truncated","complete_within_configured_scope")} for name,phase in phases.items()}


def build_feed(report: Mapping[str, Any], *, snapshot: Mapping[str, Any] | None = None, privacy: str = "hash-only", max_assets: int = 1024, max_endpoints: int = 4096, max_bytes: int = 4 * 1024 * 1024) -> dict[str, Any]:
    """Project validated evidence and deterministically remove whole tail records."""
    validate_report_shape(report)
    if report.get("schema_version") not in {"2.0","2.1","2.2"} or privacy not in {"hash-only","full"} or min(max_assets,max_endpoints,max_bytes) < 1:
        raise ValueError("invalid feed input or limits")
    assets = sorted(report.get("assets", []),key=lambda item:str(item.get("asset_id")))
    observations = sorted(report.get("observations", []),key=lambda item:(str(item.get("asset_id")),str(item.get("transport")),int(item.get("port",0))))
    selected_assets=assets[:max_assets]; allowed={item["asset_id"] for item in selected_assets}
    eligible_endpoints=[item for item in observations if item.get("asset_id") in allowed]
    selected_endpoints=eligible_endpoints[:max_endpoints]
    relation_by_asset: dict[str,list[str]]={asset:[] for asset in allowed}
    for relation in report.get("evidence_clusters", []):
        for asset in relation.get("members",[]):
            if asset in relation_by_asset: relation_by_asset[asset].append(str(relation["relation_id"]))
    asset_summaries=[]
    for asset in selected_assets:
        states={state:sum(item.get("asset_id")==asset["asset_id"] and item.get("state")==state for item in observations) for state in ("open","closed","unknown","error")}
        asset_summaries.append({"asset_id":asset["asset_id"],"addresses":[_address(str(item["address"]),privacy) for item in asset.get("addresses",[])],"states":states,"relation_refs":sorted(relation_by_asset[asset["asset_id"]])})
    endpoint_summaries=[]
    for item in selected_endpoints:
        value={"observation_id":item["observation_id"],"asset_id":item["asset_id"],"transport":item.get("transport","tcp"),"port":item["port"],"state":item["state"],"evidence_flags":sorted(key for key in ("banner","tls","http") if key in item)}
        if isinstance(item.get("service"),Mapping): value["service_hint"]=item["service"].get("name")
        endpoint_summaries.append(value)
    report_ref = str(snapshot["snapshot_id"]) if snapshot else "report_"+semantic_hash(canonical_content(report))[:24]
    feed={"feed_schema_version":"1.1" if report.get("schema_version")=="2.2" else FEED_SCHEMA_VERSION,"document_type":"scan_sensor_feed","scan_id":report["scan_id"],"target_id":report["target"]["target_id"],"report_ref":report_ref,"report_schema_version":report["schema_version"],"completed_at":report["completed_at"],"configuration_fingerprint":report.get("configuration_fingerprint") or baseline_identity(report)["configuration_fingerprint"],"coverage_summary":_coverage_summary(report),"asset_summaries":asset_summaries,"endpoint_observations":endpoint_summaries,"evidence_refs":[item["observation_id"] for item in endpoint_summaries],"event_refs":[],"truncated":len(selected_assets)<len(assets) or len(selected_endpoints)<len(eligible_endpoints),"omitted_counts":{"assets":len(assets)-len(selected_assets),"endpoints":len(eligible_endpoints)-len(selected_endpoints)},"errors_summary":{"count":len(report.get("errors",[]))}}
    minimum=dict(feed); minimum["asset_summaries"]=[]; minimum["endpoint_observations"]=[]; minimum["evidence_refs"]=[]; minimum["truncated"]=True
    if len(canonical_json(minimum).encode("utf-8"))+1 > max_bytes: raise ValueError("feed byte budget cannot hold minimum envelope")
    while len(canonical_json(feed).encode("utf-8"))+1 > max_bytes:
        feed["truncated"]=True
        if feed["endpoint_observations"]:
            feed["endpoint_observations"].pop(); feed["evidence_refs"].pop(); feed["omitted_counts"]["endpoints"]+=1
        elif feed["asset_summaries"]:
            removed=feed["asset_summaries"].pop(); feed["omitted_counts"]["assets"]+=1
            kept={item["asset_id"] for item in feed["asset_summaries"]}
            removed_count=sum(item["asset_id"] not in kept for item in feed["endpoint_observations"])
            feed["endpoint_observations"]=[item for item in feed["endpoint_observations"] if item["asset_id"] in kept]
            feed["evidence_refs"]=[item["observation_id"] for item in feed["endpoint_observations"]]; feed["omitted_counts"]["endpoints"]+=removed_count
        else: raise ValueError("feed byte budget cannot hold projected envelope")
    return feed


def validate_feed(value: Mapping[str, Any]) -> None:
    required={"feed_schema_version","document_type","scan_id","target_id","report_ref","report_schema_version","completed_at","configuration_fingerprint","coverage_summary","asset_summaries","endpoint_observations","evidence_refs","event_refs","truncated","omitted_counts","errors_summary"}
    if required-value.keys() or value.get("feed_schema_version") not in {"1.0","1.1"} or value.get("document_type")!="scan_sensor_feed": raise ValueError("invalid feed contract")
    refs=[item.get("observation_id") for item in value["endpoint_observations"]]
    if value["evidence_refs"]!=refs or len(refs)!=len(set(refs)) or any(str(value["report_ref"]).startswith(prefix) for prefix in ("/","\\")): raise ValueError("invalid feed references")
    if not isinstance(value.get("omitted_counts"), Mapping) or any(not isinstance(value["omitted_counts"].get(key), int) or value["omitted_counts"][key] < 0 for key in ("assets","endpoints")): raise ValueError("invalid feed omitted counts")
    if not value.get("truncated") and any(value["omitted_counts"].values()): raise ValueError("feed omission must be explicit")
