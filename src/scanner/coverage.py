"""Report 2.1 coverage and runtime capability descriptors."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

PHASE_ORDER = (
    "discovery",
    "endpoint_tcp",
    "banners",
    "tls",
    "dns",
    "neighbors",
    "http",
    "enrichment",
)


def phase_descriptor(
    capability_id: str,
    *,
    supported: bool,
    backend: str,
    enabled: bool,
    eligible: int = 0,
    attempted: int = 0,
    observed: int = 0,
    skipped: int = 0,
    timeout: int = 0,
    error: int = 0,
    truncated: bool = False,
    effective_limits: Mapping[str, Any] | None = None,
    reason: str | None = None,
    evidence_refs: Sequence[str] = (),
    error_refs: Sequence[str] = (),
) -> dict[str, Any]:
    """Build one coherent phase descriptor without target-state inference."""

    counts = (eligible, attempted, observed, skipped, timeout, error)
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in counts):
        raise ValueError("coverage counts must be non-negative integers")
    if attempted > eligible or observed + timeout + error > attempted:
        raise ValueError("incoherent coverage counts")
    support: dict[str, Any] = {"status": "supported" if supported else "unsupported"}
    if reason:
        support["reason"] = reason
    complete = bool(supported and enabled and not truncated and skipped == 0 and attempted == eligible)
    return {
        "capability_id": capability_id,
        "support": support,
        "backend": backend,
        "enabled": enabled,
        "eligible": eligible,
        "attempted": attempted,
        "observed": observed,
        "skipped": skipped,
        "timeout": timeout,
        "error": error,
        "truncated": truncated,
        "effective_limits": dict(effective_limits or {}),
        "complete_within_configured_scope": complete,
        "evidence_refs": sorted(set(evidence_refs)),
        "error_refs": sorted(set(error_refs)),
    }


def _endpoint_phase(items: Sequence[Mapping[str, Any]], limits: Mapping[str, Any]) -> dict[str, Any]:
    timeouts = sum(item.get("state_evidence", {}).get("result") == "timeout" for item in items)
    errors = sum(item.get("state") == "error" for item in items)
    return phase_descriptor(
        "endpoint_tcp", supported=True, backend="python_socket", enabled=True,
        eligible=len(items), attempted=len(items),
        observed=sum(item.get("state") in {"open", "closed"} for item in items),
        timeout=timeouts, error=errors, effective_limits=limits,
        evidence_refs=[str(item["observation_id"]) for item in items if item.get("observation_id")],
    )


def _nested_phase(
    capability_id: str,
    field: str,
    observations: Sequence[Mapping[str, Any]],
    *,
    enabled: bool,
    backend: str,
    limits: Mapping[str, Any],
) -> dict[str, Any]:
    eligible_items = [item for item in observations if field in item]
    statuses = [str(item[field].get("status")) for item in eligible_items]
    attempted = sum(status != "skipped" for status in statuses)
    return phase_descriptor(
        capability_id, supported=True, backend=backend, enabled=enabled,
        eligible=len(eligible_items), attempted=attempted,
        observed=sum(status == "collected" for status in statuses),
        skipped=sum(status == "skipped" for status in statuses),
        timeout=sum(status == "timeout" for status in statuses),
        error=sum(status in {"error", "handshake_failed"} for status in statuses),
        truncated=any(bool(item[field].get("truncated")) or item[field].get("error", {}).get("code") == "endpoint_limit" for item in eligible_items),
        effective_limits=limits,
        evidence_refs=[str(item["observation_id"]) for item in eligible_items],
    )


def build_coverage(
    *,
    observations: Sequence[Mapping[str, Any]],
    discovery_observations: Sequence[Mapping[str, Any]],
    name_observations: Sequence[Mapping[str, Any]],
    configuration: Mapping[str, Any],
    neighbor_observations: Sequence[Mapping[str, Any]] = (),
    neighbor_execution: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Derive ordered execution coverage solely from recorded evidence/config."""

    discovery_results = [str(item.get("result")) for item in discovery_observations]
    discovery = phase_descriptor(
        "discovery", supported=not discovery_results or "unsupported" not in discovery_results,
        backend="icmp_subprocess_and_python_socket", enabled=True,
        eligible=len(discovery_results), attempted=len(discovery_results),
        observed=sum(value in {"response", "connected", "connection_refused"} for value in discovery_results),
        timeout=sum(value == "timeout" for value in discovery_results),
        error=sum(value in {"error", "probe_error"} for value in discovery_results),
        effective_limits={
            "workers": configuration.get("workers"),
            "timeout_seconds": configuration.get("ping_timeout_seconds"),
            "max_hosts": configuration.get("max_hosts"),
        },
        reason="ping_backend_unavailable" if "unsupported" in discovery_results else None,
        evidence_refs=[str(item["discovery_observation_id"]) for item in discovery_observations],
    )
    endpoint = _endpoint_phase(observations, {"workers": configuration.get("workers"), "timeout_seconds": configuration.get("connect_timeout_seconds"), "ports": list(configuration.get("ports", []))})
    banners = _nested_phase("banners", "banner", observations, enabled=bool(configuration.get("banners_enabled")), backend="python_socket_passive_read", limits=configuration.get("banner_limits") or {})
    tls_config = configuration.get("tls", {})
    tls = _nested_phase("tls", "tls", observations, enabled=bool(tls_config.get("enabled")), backend="python_ssl", limits=tls_config)
    dns_config = configuration.get("dns", {})
    dns_statuses = [str(item.get("status")) for item in name_observations]
    dns = phase_descriptor(
        "dns", supported=True, backend="system_resolver", enabled=bool(dns_config.get("enabled")),
        eligible=len(dns_statuses), attempted=sum(value != "skipped" for value in dns_statuses),
        observed=sum(value in {"resolved", "no_name"} for value in dns_statuses),
        skipped=sum(value == "skipped" for value in dns_statuses), timeout=sum(value == "timeout" for value in dns_statuses),
        error=sum(value == "error" for value in dns_statuses), truncated=any(value == "skipped" for value in dns_statuses),
        effective_limits=dns_config,
    )
    neighbor_execution = neighbor_execution or {"supported": False, "backend": "not_implemented", "reason": "not_enabled", "eligible": 0, "attempted": 0, "truncated": False, "limits": {}}
    neighbors = phase_descriptor(
        "neighbors", supported=bool(neighbor_execution.get("supported")), backend=str(neighbor_execution.get("backend", "unknown")),
        enabled=bool(configuration.get("neighbors", {}).get("enabled")), eligible=int(neighbor_execution.get("eligible", 0)), attempted=int(neighbor_execution.get("attempted", 0)),
        observed=len(neighbor_observations), skipped=int(neighbor_execution.get("skipped", 0)), timeout=int(neighbor_execution.get("timeout", 0)), error=int(neighbor_execution.get("error", 0)),
        truncated=bool(neighbor_execution.get("truncated")), effective_limits=neighbor_execution.get("limits", {}), reason=neighbor_execution.get("reason"),
        evidence_refs=[str(item["neighbor_observation_id"]) for item in neighbor_observations],
    )
    phases = {
        "discovery": discovery,
        "endpoint_tcp": endpoint,
        "banners": banners,
        "tls": tls,
        "dns": dns,
        "neighbors": neighbors,
        "http": _nested_phase("http", "http", observations, enabled=bool(configuration.get("http", {}).get("enabled")), backend="python_socket_http", limits=configuration.get("http", {})),
        "enrichment": phase_descriptor("enrichment", supported=True, backend="deterministic_rules", enabled=True, eligible=len(observations), attempted=len(observations), observed=len(observations), effective_limits={"workers": 0}),
    }
    return {"model_version": "1.0", "phases": {name: phases[name] for name in PHASE_ORDER}}


def validate_coverage(value: Mapping[str, Any]) -> None:
    if value.get("model_version")=="2.0":
        return validate_coverage_v2(value)
    if value.get("model_version") != "1.0" or list(value.get("phases", {})) != list(PHASE_ORDER):
        raise ValueError("invalid coverage model")
    for name, phase in value["phases"].items():
        if phase.get("capability_id") != name or phase.get("support", {}).get("status") not in {"supported", "unsupported"}:
            raise ValueError("invalid coverage phase")
        phase_descriptor(
            name, supported=phase["support"]["status"] == "supported", backend=str(phase.get("backend")), enabled=bool(phase.get("enabled")),
            eligible=phase.get("eligible"), attempted=phase.get("attempted"), observed=phase.get("observed"), skipped=phase.get("skipped"), timeout=phase.get("timeout"), error=phase.get("error"),
            truncated=bool(phase.get("truncated")), effective_limits=phase.get("effective_limits", {}), reason=phase["support"].get("reason"), evidence_refs=phase.get("evidence_refs", ()), error_refs=phase.get("error_refs", ()),
        )

def coverage_v2(legacy: Mapping[str,Any], *, termination: Mapping[str,Any]|None=None, excluded: int=0, budget: Mapping[str,Any]|None=None) -> dict[str,Any]:
    """Upgrade runtime coverage without turning omissions into probe results."""
    output={}
    for name,phase in legacy.get("phases",{}).items():
        eligible=int(phase.get("eligible",0)); attempted=int(phase.get("attempted",0)); stopped=termination if termination and termination.get("phase")==name else None
        counts={"eligible":eligible+excluded if name=="discovery" else eligible,"selected":eligible,"excluded":excluded if name=="discovery" else 0,"scheduled":attempted,"started":attempted,"completed":attempted,"observed":int(phase.get("observed",0)),"timeout":int(phase.get("timeout",0)),"error":int(phase.get("error",0)),"cancelled":0,"not_started":max(0,eligible-attempted)}
        reasons={"excluded_by_policy":excluded if name=="discovery" else 0,"budget_exhausted":counts["not_started"] if stopped and stopped.get("reason_code")=="budget_exhausted" else 0,"endpoint_limit":0,"operator_interrupt":0,"dependency_not_observed":0,"capability_disabled":0 if phase.get("enabled") else eligible,"unsupported":0 if phase.get("support",{}).get("status")=="supported" else eligible}
        output[name]={"capability_id":name,"status":"partial" if stopped or counts["not_started"] else "complete","termination":dict(stopped) if stopped else None,"counts":counts,"budget":dict(budget or {"limit":None,"reserved":attempted,"consumed":attempted,"remaining":None,"unit":"work_units"}),"omission_reasons":reasons,"complete_within_configured_scope":not stopped and counts["not_started"]==0,"evidence_refs":list(phase.get("evidence_refs",[])),"error_refs":list(phase.get("error_refs",[]))}
    return {"model_version":"2.0","phases":output}

def validate_coverage_v2(value: Mapping[str,Any]) -> None:
    if list(value.get("phases",{}))!=list(PHASE_ORDER): raise ValueError("invalid coverage 2.0 phase order")
    required={"eligible","selected","excluded","scheduled","started","completed","observed","timeout","error","cancelled","not_started"}
    for name,phase in value["phases"].items():
        counts=phase.get("counts",{}); missing=required-counts.keys()
        if missing or any(isinstance(counts[k],bool) or not isinstance(counts[k],int) or counts[k]<0 for k in required): raise ValueError("invalid coverage 2.0 counts")
        if phase.get("status") not in {"complete","partial","interrupted","failed"}: raise ValueError("invalid coverage 2.0 status")
        if counts["selected"]+counts["excluded"]!=counts["eligible"] or counts["completed"]>counts["started"] or counts["started"]>counts["scheduled"] or counts["scheduled"]+counts["not_started"]!=counts["selected"]: raise ValueError("incoherent coverage 2.0 counts")
