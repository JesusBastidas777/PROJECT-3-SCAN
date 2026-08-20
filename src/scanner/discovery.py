"""Concurrent ICMP host discovery."""

from __future__ import annotations

import ipaddress
from scanner.ping import ping_host, ping_evidence
from scanner.discovery_evidence import discovery_observation
from scanner.concurrency import bounded_ordered_calls

DEFAULT_MAX_HOSTS = 4096
DEFAULT_DISCOVERY_WORKERS = 64
MAX_DISCOVERY_WORKERS = 256


class TargetValidationError(ValueError):
    """Raised when a scan target cannot be safely normalized."""


class NetworkTooLargeError(TargetValidationError):
    """Raised when a target exceeds the configured host limit."""


def normalize_network(target: object) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Parse a target, consistently clearing any CIDR host bits."""

    try:
        return ipaddress.ip_network(str(target), strict=False)
    except (TypeError, ValueError) as exc:
        raise TargetValidationError(f"invalid target: {target!r}") from exc


def candidate_host_count(
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> int:
    """Return the number of addresses yielded by ``network.hosts()``."""

    if network.version == 4:
        return network.num_addresses if network.prefixlen >= 31 else network.num_addresses - 2
    return network.num_addresses if network.prefixlen >= 127 else network.num_addresses - 1


def validate_network(
    target: object, *, max_hosts: int = DEFAULT_MAX_HOSTS
) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Normalize *target* and enforce the configured safety limit."""

    network_obj = normalize_network(target)
    if isinstance(max_hosts, bool) or not isinstance(max_hosts, int) or max_hosts < 1:
        raise ValueError("max_hosts must be a positive integer")

    host_count = candidate_host_count(network_obj)
    if host_count > max_hosts:
        raise NetworkTooLargeError(
            f"target {network_obj} contains {host_count} usable hosts; "
            f"configured limit is {max_hosts}"
        )
    return network_obj


def _worker_count(requested: int, task_count: int) -> int:
    if isinstance(requested, bool) or not isinstance(requested, int) or requested < 1:
        raise ValueError("discovery workers must be a positive integer")
    return min(requested, MAX_DISCOVERY_WORKERS, max(1, task_count))


def discover_hosts(
    network: object,
    *,
    timeout: float = 1.0,
    max_workers: int = DEFAULT_DISCOVERY_WORKERS,
    max_hosts: int = DEFAULT_MAX_HOSTS,
) -> list[str]:
    """Discover responsive hosts in *network* with bounded concurrency."""

    network_obj = validate_network(network, max_hosts=max_hosts)

    hosts = list(network_obj.hosts())
    if not hosts:
        return []

    workers = _worker_count(max_workers, len(hosts))
    active_hosts: list[str] = []
    results = bounded_ordered_calls(ping_host, [(host, timeout) for host in hosts], max_workers=workers)
    for host, result in zip(hosts, results):
        if result is True:
            active_hosts.append(str(host))

    return active_hosts


def discover_host_evidence(network: object, *, timeout: float = 1.0, max_workers: int = DEFAULT_DISCOVERY_WORKERS, max_hosts: int = DEFAULT_MAX_HOSTS) -> list[dict[str, object]]:
    """Collect one ordered, structured ICMP observation per candidate address."""

    network_obj = validate_network(network, max_hosts=max_hosts)
    hosts = list(network_obj.hosts())
    if not hosts:
        return []
    workers = _worker_count(max_workers, len(hosts))
    results = bounded_ordered_calls(ping_evidence, [(host, timeout) for host in hosts], max_workers=workers)
    return [
        discovery_observation(host, "probe_error", error_code="worker_error") if isinstance(result, Exception) else result
        for host, result in zip(hosts, results)
    ]
