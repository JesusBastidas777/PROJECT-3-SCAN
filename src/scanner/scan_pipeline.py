"""Acquisition orchestration independent from CLI and filesystem output."""
from __future__ import annotations
import time
from typing import Any
from scanner.banners import collect_open_banners
from scanner.configuration import ResolvedScanConfiguration
from scanner.contract import build_report_v2, build_report_v21
from scanner.discovery import discover_host_evidence, validate_network
from scanner.discovery_tcp import collect_tcp_discovery, responsive_addresses, reusable_endpoint_observations
from scanner.dns import collect_name_observations
from scanner.http_probe import collect_open_http, MAX_HTTP_WORKERS, DEFAULT_HTTP_PORTS
from scanner.neighbors import collect_neighbor_evidence
from scanner.ports import scan_hosts
from scanner.report import build_report, utc_timestamp
from scanner.tls import collect_open_tls, DEFAULT_TLS_PORTS
from scanner.target_policy import apply_target_policy
from scanner.ping import ping_evidence
from scanner.concurrency import bounded_ordered_calls
from scanner.discovery_evidence import discovery_observation
from scanner.budgets import ExecutionBudgets

def execute_scan(configuration: ResolvedScanConfiguration) -> dict[str, Any]:
    """Acquire evidence from one fully resolved immutable configuration."""
    a=configuration.namespace(); network=validate_network(a.target,max_hosts=a.max_hosts); p=configuration.target_selection
    selection=apply_target_policy(network,include_hosts=p.include_hosts,exclude_hosts=p.exclude_hosts,include_cidrs=p.include_cidrs,exclude_cidrs=p.exclude_cidrs)
    budgets=ExecutionBudgets(max_runtime=a.max_runtime,max_network_attempts=a.max_network_attempts,max_evidence_bytes=a.max_evidence_bytes,max_evidence_records=a.max_evidence_records)
    probe_selected=list(selection.selected); discovery_omitted=0
    if a.max_network_attempts is not None:
        per_host=len(a.discovery_ports) if a.discovery=="tcp" else 1; allowed=a.max_network_attempts//max(1,per_host); discovery_omitted=max(0,len(probe_selected)-allowed); probe_selected=probe_selected[:allowed]
    budgets.reserve("network_attempts",len(probe_selected)*(len(a.discovery_ports) if a.discovery=="tcp" else 1))
    timestamp=utc_timestamp(); started=time.monotonic(); mode=a.discovery
    if mode=="tcp": discovery=[]
    elif not discovery_omitted and len(selection.selected)==sum(1 for _ in network.hosts()): discovery=discover_host_evidence(network,timeout=a.ping_timeout,max_workers=a.workers,max_hosts=a.max_hosts)
    else:
        values=bounded_ordered_calls(ping_evidence,[(host,a.ping_timeout) for host in probe_selected],max_workers=min(a.workers,max(1,len(probe_selected)))) if probe_selected else []
        discovery=[discovery_observation(host,"probe_error",error_code="worker_error") if isinstance(value,Exception) else value for host,value in zip(probe_selected,values)]
    candidates=list(probe_selected)
    if mode=="icmp-tcp": candidates=[item["address"] for item in discovery if item["result"]!="response"]
    tcp=[]
    if mode in {"icmp-tcp","tcp"}:
        tcp=collect_tcp_discovery(candidates,a.discovery_ports,timeout=a.discovery_connect_timeout,max_workers=a.workers,max_endpoints=a.max_discovery_endpoints); discovery.extend(tcp)
    active=responsive_addresses(discovery)
    endpoint_omitted=0
    if a.max_network_attempts is not None:
        discovery_attempts=len(discovery); remaining=max(0,a.max_network_attempts-discovery_attempts); allowed_hosts=remaining//max(1,len(a.ports)); endpoint_omitted=max(0,(len(active)-allowed_hosts)*len(a.ports)); active=active[:allowed_hosts]
    budgets.reserve("network_attempts",len(active)*len(a.ports))
    hosts=scan_hosts(active,a.ports,timeout=a.connect_timeout,max_workers=a.workers)
    reusable=reusable_endpoint_observations(tcp)
    for host,items in hosts.items(): hosts[host]=[reusable.get((host,int(item["port"])),item) for item in items]
    if a.collect_tls: hosts=collect_open_tls(hosts,ports=a.tls_ports,workers=a.tls_workers,max_endpoints=a.tls_max_endpoints,connect_timeout=a.tls_connect_timeout,handshake_timeout=a.tls_handshake_timeout)
    if a.collect_http:
        if a.schema_version not in {"2.1","2.2"}: raise ValueError("--collect-http requires --schema-version 2.1 or 2.2")
        if a.http_workers>MAX_HTTP_WORKERS: raise ValueError(f"HTTP workers must not exceed {MAX_HTTP_WORKERS}")
        hosts=collect_open_http(hosts,ports=a.http_ports,workers=a.http_workers,max_endpoints=a.http_max_endpoints,method_mode=a.http_method,connect_timeout=a.http_connect_timeout,tls_timeout=a.http_tls_timeout,read_timeout=a.http_read_timeout,max_header_bytes=a.http_max_header_bytes,body_hash_bytes=a.http_body_hash_bytes)
    names=collect_name_observations(active,workers=a.dns_workers,timeout=a.dns_timeout,max_assets=a.dns_max_assets) if a.resolve_names else []
    if a.collect_banners: hosts=collect_open_banners(hosts,workers=min(a.banner_workers,32),max_endpoints=a.banner_max_endpoints,connect_timeout=a.connect_timeout,read_timeout=a.banner_read_timeout,max_bytes=a.banner_max_bytes)
    neighbor=[]; neighbor_exec={"supported":False,"backend":"not_enabled","reason":"not_enabled","eligible":0,"attempted":0,"truncated":False,"limits":{"workers":0}}
    if a.collect_neighbors:
        if a.schema_version not in {"2.1","2.2"}: raise ValueError("--collect-neighbors requires --schema-version 2.1 or 2.2")
        neighbor,neighbor_exec=collect_neighbor_evidence(network,privacy=a.neighbor_privacy,max_records=a.neighbor_max_records,timeout=a.neighbor_timeout,interface=a.neighbor_interface)
    duration=max(0,round((time.monotonic()-started)*1000))
    if a.schema_version in {"2.0","2.1","2.2"}:
        builder=build_report_v21 if a.schema_version in {"2.1","2.2"} else build_report_v2
        extra={}
        if a.schema_version in {"2.1","2.2"}: extra={"neighbor_observations":neighbor,"neighbor_execution":neighbor_exec,"neighbor_configuration":{"enabled":a.collect_neighbors,"privacy":a.neighbor_privacy,"max_records":a.neighbor_max_records,"timeout_seconds":a.neighbor_timeout,"interface":a.neighbor_interface},"http_configuration":{"enabled":a.collect_http,"ports":a.http_ports,"workers":a.http_workers,"max_endpoints":a.http_max_endpoints,"connect_timeout_seconds":a.http_connect_timeout,"tls_timeout_seconds":a.http_tls_timeout,"read_timeout_seconds":a.http_read_timeout,"max_header_bytes":a.http_max_header_bytes,"body_hash_bytes":a.http_body_hash_bytes,"method":a.http_method},"correlation_configuration":{"enabled":a.correlate_evidence,"max_signals":a.correlation_max_signals,"max_relations":a.correlation_max_relations,"ruleset_version":"1.0"}}
        report=builder(target_input=a.target,network=network,host_results=hosts,ports=a.ports,started_at=timestamp,completed_at=utc_timestamp(),duration_ms=duration,ping_timeout=a.ping_timeout,connect_timeout=a.connect_timeout,workers=a.workers,max_hosts=a.max_hosts,banners_enabled=a.collect_banners,banner_limits={"workers":min(a.banner_workers,32),"max_endpoints":a.banner_max_endpoints,"max_bytes":a.banner_max_bytes,"read_timeout_seconds":a.banner_read_timeout},discovery_observations=discovery,discovery_configuration={"mode":mode,"ports":a.discovery_ports,"connect_timeout_seconds":a.discovery_connect_timeout,"max_endpoints":a.max_discovery_endpoints},tls_configuration={"enabled":a.collect_tls,"ports":a.tls_ports,"workers":a.tls_workers,"max_endpoints":a.tls_max_endpoints,"connect_timeout_seconds":a.tls_connect_timeout,"handshake_timeout_seconds":a.tls_handshake_timeout},name_observations=names,dns_configuration={"enabled":a.resolve_names,"workers":a.dns_workers,"timeout_seconds":a.dns_timeout,"timeout_guarantee":"best_effort","max_assets":a.dns_max_assets},profile_configuration={"name":a.profile,"version":a.profile_version,"overrides":getattr(a,"profile_overrides",[])},**extra)
        if a.schema_version in {"2.1","2.2"}:
            from scanner.contract import semantic_hash
            report["configuration"]["target_selection"]=selection.policy; report["effective_configuration"]=dict(report["configuration"]); report["configuration_fingerprint"]=semantic_hash(report["effective_configuration"])
        if a.schema_version=="2.2":
            from scanner.coverage import coverage_v2
            from scanner.baselines import baseline_identity
            term=None
            if discovery_omitted: term={"reason_code":"budget_exhausted","phase":"discovery","budget_id":"network_attempts","occurred_at":report["completed_at"]}
            elif endpoint_omitted: term={"reason_code":"budget_exhausted","phase":"endpoint_tcp","budget_id":"network_attempts","occurred_at":report["completed_at"]}
            report["schema_version"]="2.2"; report["coverage"]=coverage_v2(report["coverage"],termination=term,excluded=len(selection.excluded),budget=budgets.descriptor("network_attempts","attempts")); report["partial"]=bool(term); report["termination"]=term
            if discovery_omitted:
                c=report["coverage"]["phases"]["discovery"]["counts"]; c.update(eligible=len(selection.selected)+len(selection.excluded),selected=len(selection.selected),excluded=len(selection.excluded),scheduled=len(discovery),started=len(discovery),completed=len(discovery),not_started=discovery_omitted); report["coverage"]["phases"]["discovery"]["omission_reasons"]["budget_exhausted"]=discovery_omitted
            if endpoint_omitted:
                c=report["coverage"]["phases"]["endpoint_tcp"]["counts"]; c["eligible"]+=endpoint_omitted; c["selected"]+=endpoint_omitted; c["not_started"]+=endpoint_omitted; report["coverage"]["phases"]["endpoint_tcp"]["omission_reasons"]["budget_exhausted"]=endpoint_omitted
            ids=baseline_identity(report); report["measurement_scope_fingerprint"]=ids["measurement_scope_fingerprint"]; report["execution_policy_fingerprint"]=semantic_hash({"max_runtime":a.max_runtime,"max_network_attempts":a.max_network_attempts,"max_evidence_bytes":a.max_evidence_bytes,"max_evidence_records":a.max_evidence_records,"max_pending":a.max_pending})
            from scanner.resume import acquisition_provenance,validate_resume
            resumed=None; previous=[]
            if a.resume:
                from scanner.checkpoints import load_checkpoint
                resumed=load_checkpoint(a.resume); validate_resume(resumed,target_id=report["target"]["target_id"],measurement_scope_fingerprint=report["measurement_scope_fingerprint"],execution_policy_fingerprint=report["execution_policy_fingerprint"]); previous=resumed.get("acquisition",{}).get("segments",[])
            report["acquisition"]=acquisition_provenance(started_at=report["started_at"],completed_at=report["completed_at"],resumed_from=resumed.get("checkpoint_id") if resumed else None,previous_segments=previous); report["baseline_eligible"]=not report["partial"] and not resumed
        return report
    return build_report(target_input=a.target,network=network,host_port_results=hosts,ports=a.ports,timestamp=timestamp,duration_ms=duration,ping_timeout=a.ping_timeout,connect_timeout=a.connect_timeout,workers=a.workers,max_hosts=a.max_hosts)
