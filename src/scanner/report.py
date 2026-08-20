"""Versioned SCAN report construction and JSON serialization."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
import tempfile
from collections.abc import Mapping, Sequence
from typing import Any

from scanner.discovery import candidate_host_count, normalize_network

SCHEMA_VERSION = "1.0"
SCANNER_NAME = "SCAN"
SCANNER_VERSION = "1.0.0"


def utc_timestamp(now: datetime | None = None) -> str:
    """Return an ISO-8601 UTC timestamp ending in ``Z``."""

    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("timestamp must include timezone information")
    return current.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def build_host_report(host: str, ports: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Build one deterministic host record from TCP scan facts."""

    port_records = [dict(port) for port in ports]
    open_ports = [port["port"] for port in port_records if port["status"] == "OPEN"]
    closed_count = sum(port["status"] == "CLOSED" for port in port_records)
    error_count = len(port_records) - len(open_ports) - closed_count
    return {
        "host": host,
        "ports": port_records,
        "open_ports": open_ports,
        "open_count": len(open_ports),
        "closed_count": closed_count,
        "error_count": error_count,
    }


def build_report(
    *,
    target_input: str,
    network: object,
    host_port_results: Mapping[str, Sequence[Mapping[str, Any]]],
    ports: Sequence[int],
    timestamp: str,
    duration_ms: int,
    ping_timeout: float,
    connect_timeout: float,
    workers: int,
    max_hosts: int,
) -> dict[str, Any]:
    """Construct the stable schema-v1 report without performing I/O."""

    network_obj = normalize_network(network)
    if duration_ms < 0:
        raise ValueError("duration_ms cannot be negative")

    hosts = [
        build_host_report(host, port_results)
        for host, port_results in host_port_results.items()
    ]
    total_open = sum(host["open_count"] for host in hosts)
    total_closed = sum(host["closed_count"] for host in hosts)
    total_errors = sum(host["error_count"] for host in hosts)
    ports_scanned = sum(len(host["ports"]) for host in hosts)
    canonical_network = str(network_obj)

    return {
        "schema_version": SCHEMA_VERSION,
        "scanner": {"name": SCANNER_NAME, "version": SCANNER_VERSION},
        "network": canonical_network,
        "target": {
            "input": target_input,
            "network": canonical_network,
            "ip_version": network_obj.version,
            "candidate_hosts": candidate_host_count(network_obj),
        },
        "timestamp": timestamp,
        "duration_ms": duration_ms,
        "summary": {
            "active_hosts": len(hosts),
            "hosts_scanned": len(hosts),
            "ports_scanned": ports_scanned,
            "total_open_ports": total_open,
            "total_closed_ports": total_closed,
            "total_errors": total_errors,
        },
        "hosts": hosts,
        "metadata": {
            "discovery": "icmp",
            "ports": list(ports),
            "ping_timeout_seconds": ping_timeout,
            "connect_timeout_seconds": connect_timeout,
            "workers": workers,
            "max_hosts": max_hosts,
        },
    }


def serialize_report(report: Mapping[str, Any]) -> str:
    """Serialize a report as deterministic, human-readable UTF-8 JSON text."""

    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


def write_report_atomic(report: Mapping[str, Any], output_path: Path) -> None:
    """Atomically replace *output_path* with a complete serialized report."""

    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            temporary_file.write(serialize_report(report))
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_path, destination)
        temporary_path = None
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass
