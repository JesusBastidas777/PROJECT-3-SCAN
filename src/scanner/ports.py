"""Bounded concurrent TCP port scanning."""

from __future__ import annotations

import ipaddress
import socket
import errno
from concurrent.futures import ThreadPoolExecutor
from collections.abc import Iterable

from scanner.observations import tcp_observation

DEFAULT_PORT_WORKERS = 64
MAX_PORT_WORKERS = 256


def _validate_port(port: object) -> int:
    if isinstance(port, bool) or not isinstance(port, int):
        raise ValueError(f"port must be an integer: {port!r}")
    if not 1 <= port <= 65535:
        raise ValueError(f"port must be between 1 and 65535: {port}")
    return port


def _normalize_ports(ports: Iterable[object]) -> list[int]:
    normalized: list[int] = []
    seen: set[int] = set()
    try:
        iterator = iter(ports)
    except TypeError as exc:
        raise ValueError("ports must be an iterable of integers") from exc

    for value in iterator:
        port = _validate_port(value)
        if port not in seen:
            seen.add(port)
            normalized.append(port)
    return normalized


def _worker_count(requested: int, task_count: int) -> int:
    if isinstance(requested, bool) or not isinstance(requested, int) or requested < 1:
        raise ValueError("port workers must be a positive integer")
    return min(requested, MAX_PORT_WORKERS, max(1, task_count))


def _worker_error(port: int) -> dict[str, object]:
    return tcp_observation(port, "error", "worker_error", error_code="worker_error")


def scan_port(ip: object, port: int, timeout: float = 1.0) -> dict[str, object]:
    """Scan one TCP port and return normalized evidence."""

    port = _validate_port(port)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        raise ValueError("connection timeout must be a positive number")

    try:
        address = ipaddress.ip_address(str(ip))
    except (TypeError, ValueError):
        return tcp_observation(port, "error", "invalid_address", error_code="invalid_address")

    family = socket.AF_INET if address.version == 4 else socket.AF_INET6
    endpoint = (str(address), port) if family == socket.AF_INET else (str(address), port, 0, 0)

    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex(endpoint)
    except socket.timeout:
        return tcp_observation(port, "unknown", "timeout", error_code="timeout")
    except ValueError:
        return tcp_observation(port, "error", "local_error", error_code="local_error")
    except OSError as exc:
        if exc.errno in {errno.ENETUNREACH, errno.EHOSTUNREACH}:
            return tcp_observation(port, "unknown", "unreachable", error_code="unreachable")
        return tcp_observation(port, "error", "local_error", error_code="local_error")

    if result == 0:
        return tcp_observation(port, "open", "connected")
    if result in {errno.ECONNREFUSED, 10061}:
        return tcp_observation(port, "closed", "connection_refused")
    if result in {errno.ETIMEDOUT, 10060}:
        return tcp_observation(port, "unknown", "timeout", error_code="timeout")
    if result in {errno.ENETUNREACH, errno.EHOSTUNREACH, 10051, 10065}:
        return tcp_observation(port, "unknown", "unreachable", error_code="unreachable")
    return tcp_observation(port, "unknown", "connect_failed", error_code="connect_failed")


def scan_ports(
    ip: object,
    ports: Iterable[object],
    *,
    timeout: float = 1.0,
    max_workers: int = DEFAULT_PORT_WORKERS,
) -> list[dict[str, object]]:
    """Scan unique ports on one host while preserving their input order."""

    normalized_ports = _normalize_ports(ports)
    if not normalized_ports:
        return []

    workers = _worker_count(max_workers, len(normalized_ports))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(scan_port, ip, port, timeout) for port in normalized_ports
        ]
        results: list[dict[str, object]] = []
        for port, future in zip(normalized_ports, futures):
            try:
                results.append(future.result())
            except KeyboardInterrupt:
                raise
            except Exception:
                results.append(_worker_error(port))
    return results


def scan_hosts(
    hosts: Iterable[object],
    ports: Iterable[object],
    *,
    timeout: float = 1.0,
    max_workers: int = DEFAULT_PORT_WORKERS,
) -> dict[str, list[dict[str, object]]]:
    """Scan multiple hosts using one globally bounded executor."""

    normalized_hosts: list[str] = []
    seen_hosts: set[str] = set()
    for host in hosts:
        try:
            normalized = str(ipaddress.ip_address(str(host)))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid host: {host!r}") from exc
        if normalized not in seen_hosts:
            seen_hosts.add(normalized)
            normalized_hosts.append(normalized)

    normalized_ports = _normalize_ports(ports)
    results = {host: [] for host in normalized_hosts}
    task_count = len(normalized_hosts) * len(normalized_ports)
    if task_count == 0:
        return results

    workers = _worker_count(max_workers, task_count)
    tasks: list[tuple[str, int, object]] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        for host in normalized_hosts:
            for port in normalized_ports:
                tasks.append((host, port, executor.submit(scan_port, host, port, timeout)))
        for host, port, future in tasks:
            try:
                results[host].append(future.result())
            except KeyboardInterrupt:
                raise
            except Exception:
                results[host].append(_worker_error(port))
    return results
