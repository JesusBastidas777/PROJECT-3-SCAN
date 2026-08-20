"""Bounded TCP discovery evidence without availability claims."""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from typing import Any

from scanner.concurrency import bounded_ordered_calls
from scanner.discovery_evidence import discovery_observation
from scanner.ports import scan_port


def tcp_discovery_probe(address: object, port: int, timeout: float) -> dict[str, Any]:
    endpoint = scan_port(address, port, timeout)
    result_map = {
        "connected": "connected",
        "connection_refused": "connection_refused",
        "timeout": "timeout",
        "unreachable": "unreachable",
    }
    result = result_map.get(str(endpoint["state_evidence"]["result"]), "error")
    value = discovery_observation(address, result, method="tcp_connect", error_code="tcp_probe_error" if result == "error" else None, port=port)
    value["endpoint_observation"] = endpoint
    return value


def collect_tcp_discovery(addresses: Sequence[object], ports: Sequence[int], *, timeout: float, max_workers: int, max_endpoints: int) -> list[dict[str, Any]]:
    canonical = [str(ipaddress.ip_address(str(address))) for address in addresses]
    unique_ports = list(dict.fromkeys(ports))
    tasks = [(address, port, timeout) for address in canonical for port in unique_ports]
    if len(tasks) > max_endpoints:
        raise ValueError(f"TCP discovery requires {len(tasks)} endpoints; configured limit is {max_endpoints}")
    if not tasks:
        return []
    values = bounded_ordered_calls(tcp_discovery_probe, tasks, max_workers=min(max_workers, len(tasks)))
    output = []
    for (address, port, _), value in zip(tasks, values):
        if isinstance(value, Exception):
            value = discovery_observation(address, "error", method="tcp_connect", error_code="worker_error", port=port)
        output.append(value)
    return output


def responsive_addresses(observations: Sequence[dict[str, Any]]) -> list[str]:
    responsive = {item["address"] for item in observations if item["result"] in {"response", "connected", "connection_refused"}}
    return sorted(responsive, key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value))))


def reusable_endpoint_observations(observations: Sequence[dict[str, Any]]) -> dict[tuple[str, int], dict[str, Any]]:
    return {(item["address"], int(item["port"])): dict(item["endpoint_observation"]) for item in observations if item.get("result") in {"connected", "connection_refused"} and "endpoint_observation" in item}
