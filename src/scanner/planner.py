"""Pure deterministic scan planning with no acquisition side effects."""
from __future__ import annotations
import ipaddress
from typing import Any
from scanner.configuration import ResolvedScanConfiguration
from scanner.contract import semantic_hash
from scanner.discovery import candidate_host_count, validate_network
from scanner.inventory import target_id

MAX_LISTED_PLAN_HOSTS=256

def build_scan_plan(configuration: ResolvedScanConfiguration) -> dict[str,Any]:
    a=configuration.namespace(); network=validate_network(a.target,max_hosts=a.max_hosts); count=candidate_host_count(network)
    listed=[str(value) for _,value in zip(range(MAX_LISTED_PLAN_HOSTS),network.hosts())]
    phases=["discovery","endpoint_tcp"]+[name for name in ("banners","tls","dns","neighbors","http") if name in configuration.measurement.capabilities]+["enrichment"]
    effective={"schema_version":a.schema_version,"profile":{"name":a.profile,"version":a.profile_version},"ports":list(configuration.measurement.ports),"discovery":{"mode":a.discovery,"ports":list(a.discovery_ports)},"workers":a.workers,"timeouts":{"ping":a.ping_timeout,"connect":a.connect_timeout,"discovery_connect":a.discovery_connect_timeout},"limits":{"max_hosts":a.max_hosts,"max_discovery_endpoints":a.max_discovery_endpoints,"banner_max_endpoints":a.banner_max_endpoints,"banner_max_bytes":a.banner_max_bytes,"tls_max_endpoints":a.tls_max_endpoints,"dns_max_assets":a.dns_max_assets,"neighbor_max_records":a.neighbor_max_records,"http_max_endpoints":a.http_max_endpoints,"http_max_header_bytes":a.http_max_header_bytes,"http_body_hash_bytes":a.http_body_hash_bytes},"privacy":{"events":a.events_privacy,"neighbors":a.neighbor_privacy}}
    semantic={"target":str(network),"effective_configuration":effective,"phases":phases}
    return {"plan_schema_version":"1.0","document_type":"scan_plan","plan_id":"plan_"+semantic_hash(semantic)[:24],"target":{"input":a.target,"network":str(network),"target_id":target_id(str(network)),"ip_version":network.version,"candidate_hosts":count,"selected_hosts":{"count":count,"items":listed,"truncated":count>len(listed)},"excluded_hosts":{"count":0,"reason":"none"}},"ports":list(configuration.measurement.ports),"discovery_strategy":a.discovery,"phases":phases,"capabilities":list(configuration.measurement.capabilities),"effective_profile":effective["profile"],"effective_configuration":effective,"measurement_scope":semantic,"execution_policy":{"workers":a.workers,"timeouts":effective["timeouts"],"limits":effective["limits"]},"potential_maximum_network_attempts":{"kind":"structural_upper_bound_not_prediction","count":count*(1+len(a.ports))},"privacy":effective["privacy"],"expected_output_contracts":{"report":a.schema_version,"events":"1.0" if a.events_output else None,"snapshot":"1.1" if a.history_dir and a.schema_version=="2.1" else "1.0" if a.history_dir else None}}
