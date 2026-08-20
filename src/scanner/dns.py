"""Bounded, untrusted reverse-DNS name evidence."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Sequence
from typing import Any, Callable

from scanner.concurrency import bounded_ordered_calls

MAX_DNS_WORKERS = 16


def normalize_hostname(value: str) -> str:
    labels = value.rstrip(".").split(".")
    normalized = []
    for label in labels:
        if not label:
            raise ValueError("empty hostname label")
        normalized.append(label.encode("idna").decode("ascii").lower())
    return ".".join(normalized)


def reverse_dns(address: object, timeout: float, resolver: Callable[[str], tuple[str, list[str], list[str]]] = socket.gethostbyaddr) -> dict[str, Any]:
    """Resolve PTR evidence; timeout is best-effort with the system resolver."""

    if timeout <= 0:
        raise ValueError("DNS timeout must be positive")
    canonical = str(ipaddress.ip_address(str(address)))
    base: dict[str, Any] = {"address": canonical, "source": "ptr", "trusted": False, "timeout_guarantee": "best_effort"}
    try:
        primary, aliases, _ = resolver(canonical)
        names = sorted({normalize_hostname(name) for name in [primary, *aliases]})
    except (socket.herror, socket.gaierror):
        return {**base, "status": "no_name"}
    except (socket.timeout, TimeoutError):
        return {**base, "status": "timeout", "error": {"code": "timeout"}}
    except (OSError, UnicodeError, ValueError):
        return {**base, "status": "error", "error": {"code": "resolver_error"}}
    return {**base, "status": "resolved", "names": names}


def collect_name_observations(addresses: Sequence[object], *, workers: int = 4, timeout: float = 1.0, max_assets: int = 256, resolver: Callable[[str], tuple[str, list[str], list[str]]] = socket.gethostbyaddr) -> list[dict[str, Any]]:
    if not 1 <= workers <= MAX_DNS_WORKERS or max_assets < 1:
        raise ValueError("invalid DNS limits")
    canonical = sorted({str(ipaddress.ip_address(str(address))) for address in addresses}, key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value))))
    selected = canonical[:max_assets]
    tasks = [(address, timeout, resolver) for address in selected]
    values = bounded_ordered_calls(reverse_dns, tasks, max_workers=min(workers, max(1, len(tasks)))) if tasks else []
    output = [{"address": address, "source": "ptr", "status": "error", "trusted": False, "timeout_guarantee": "best_effort", "error": {"code": "worker_error"}} if isinstance(value, Exception) else value for address, value in zip(selected, values)]
    output.extend({"address": address, "source": "ptr", "status": "skipped", "trusted": False, "timeout_guarantee": "best_effort", "error": {"code": "asset_limit"}} for address in canonical[max_assets:])
    return output
