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

def execute_scan(configuration: ResolvedScanConfiguration) -> dict[str, Any]:
    """Acquire evidence from one fully resolved immutable configuration."""
    a=configuration.namespace(); network=validate_network(a.target,max_hosts=a.max_hosts)
    timestamp=utc_timestamp(); started=time.monotonic(); mode=a.discovery
    discovery=[] if mode=="tcp" else discover_host_evidence(network,timeout=a.ping_timeout,max_workers=a.workers,max_hosts=a.max_hosts)
    candidates=[str(address) for address in network.hosts()]
    if mode=="icmp-tcp": candidates=[item["address"] for item in discovery if item["result"]!="response"]
    tcp=[]
    if mode in {"icmp-tcp","tcp"}:
        tcp=collect_tcp_discovery(candidates,a.discovery_ports,timeout=a.discovery_connect_timeout,max_workers=a.workers,max_endpoints=a.max_discovery_endpoints); discovery.extend(tcp)
    active=responsive_addresses(discovery); hosts=scan_hosts(active,a.ports,timeout=a.connect_timeout,max_workers=a.workers)
    reusable=reusable_endpoint_observations(tcp)
    for host,items in hosts.items(): hosts[host]=[reusable.get((host,int(item["port"])),item) for item in items]
    if a.collect_tls: hosts=collect_open_tls(hosts,ports=a.tls_ports,workers=a.tls_workers,max_endpoints=a.tls_max_endpoints,connect_timeout=a.tls_connect_timeout,handshake_timeout=a.tls_handshake_timeout)
    if a.collect_http:
        if a.schema_version!="2.1": raise ValueError("--collect-http requires --schema-version 2.1")
        if a.http_workers>MAX_HTTP_WORKERS: raise ValueError(f"HTTP workers must not exceed {MAX_HTTP_WORKERS}")
        hosts=collect_open_http(hosts,ports=a.http_ports,workers=a.http_workers,max_endpoints=a.http_max_endpoints,method_mode=a.http_method,connect_timeout=a.http_connect_timeout,tls_timeout=a.http_tls_timeout,read_timeout=a.http_read_timeout,max_header_bytes=a.http_max_header_bytes,body_hash_bytes=a.http_body_hash_bytes)
    names=collect_name_observations(active,workers=a.dns_workers,timeout=a.dns_timeout,max_assets=a.dns_max_assets) if a.resolve_names else []
    if a.collect_banners: hosts=collect_open_banners(hosts,workers=min(a.banner_workers,32),max_endpoints=a.banner_max_endpoints,connect_timeout=a.connect_timeout,read_timeout=a.banner_read_timeout,max_bytes=a.banner_max_bytes)
    neighbor=[]; neighbor_exec={"supported":False,"backend":"not_enabled","reason":"not_enabled","eligible":0,"attempted":0,"truncated":False,"limits":{"workers":0}}
    if a.collect_neighbors:
        if a.schema_version!="2.1": raise ValueError("--collect-neighbors requires --schema-version 2.1")
        neighbor,neighbor_exec=collect_neighbor_evidence(network,privacy=a.neighbor_privacy,max_records=a.neighbor_max_records,timeout=a.neighbor_timeout,interface=a.neighbor_interface)
    duration=max(0,round((time.monotonic()-started)*1000))
    if a.schema_version in {"2.0","2.1"}:
        builder=build_report_v21 if a.schema_version=="2.1" else build_report_v2
        extra={}
        if a.schema_version=="2.1": extra={"neighbor_observations":neighbor,"neighbor_execution":neighbor_exec,"neighbor_configuration":{"enabled":a.collect_neighbors,"privacy":a.neighbor_privacy,"max_records":a.neighbor_max_records,"timeout_seconds":a.neighbor_timeout,"interface":a.neighbor_interface},"http_configuration":{"enabled":a.collect_http,"ports":a.http_ports,"workers":a.http_workers,"max_endpoints":a.http_max_endpoints,"connect_timeout_seconds":a.http_connect_timeout,"tls_timeout_seconds":a.http_tls_timeout,"read_timeout_seconds":a.http_read_timeout,"max_header_bytes":a.http_max_header_bytes,"body_hash_bytes":a.http_body_hash_bytes,"method":a.http_method},"correlation_configuration":{"enabled":a.correlate_evidence,"max_signals":a.correlation_max_signals,"max_relations":a.correlation_max_relations,"ruleset_version":"1.0"}}
        return builder(target_input=a.target,network=network,host_results=hosts,ports=a.ports,started_at=timestamp,completed_at=utc_timestamp(),duration_ms=duration,ping_timeout=a.ping_timeout,connect_timeout=a.connect_timeout,workers=a.workers,max_hosts=a.max_hosts,banners_enabled=a.collect_banners,banner_limits={"workers":min(a.banner_workers,32),"max_endpoints":a.banner_max_endpoints,"max_bytes":a.banner_max_bytes,"read_timeout_seconds":a.banner_read_timeout},discovery_observations=discovery,discovery_configuration={"mode":mode,"ports":a.discovery_ports,"connect_timeout_seconds":a.discovery_connect_timeout,"max_endpoints":a.max_discovery_endpoints},tls_configuration={"enabled":a.collect_tls,"ports":a.tls_ports,"workers":a.tls_workers,"max_endpoints":a.tls_max_endpoints,"connect_timeout_seconds":a.tls_connect_timeout,"handshake_timeout_seconds":a.tls_handshake_timeout},name_observations=names,dns_configuration={"enabled":a.resolve_names,"workers":a.dns_workers,"timeout_seconds":a.dns_timeout,"timeout_guarantee":"best_effort","max_assets":a.dns_max_assets},profile_configuration={"name":a.profile,"version":a.profile_version,"overrides":getattr(a,"profile_overrides",[])},**extra)
    return build_report(target_input=a.target,network=network,host_port_results=hosts,ports=a.ports,timestamp=timestamp,duration_ms=duration,ping_timeout=a.ping_timeout,connect_timeout=a.connect_timeout,workers=a.workers,max_hosts=a.max_hosts)
