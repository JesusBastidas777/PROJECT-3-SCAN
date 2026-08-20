"""Optional, bounded and untrusted passive banner collection."""

from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import ipaddress
import socket
from collections.abc import Mapping, Sequence
from typing import Any

DEFAULT_BANNER_WORKERS = 8
MAX_BANNER_WORKERS = 32
DEFAULT_MAX_ENDPOINTS = 64
DEFAULT_MAX_BYTES = 1024


def _result(status: str, *, data: bytes = b"", truncated: bool = False, error: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": status,
        "method": "passive_read",
        "bytes_captured": len(data),
        "truncated": truncated,
        "trusted": False,
    }
    if data:
        result["sha256"] = hashlib.sha256(data).hexdigest()
        try:
            result.update({"encoding": "utf-8", "text": data.decode("utf-8")})
        except UnicodeDecodeError:
            result.update({"encoding": "base64", "data_base64": base64.b64encode(data).decode("ascii")})
    if error:
        result["error"] = {"code": error}
    return result


def collect_banner(host: str, port: int, *, connect_timeout: float = 0.5, read_timeout: float = 0.5, max_bytes: int = DEFAULT_MAX_BYTES) -> dict[str, Any]:
    """Passively read at most *max_bytes* plus one truncation-detection byte."""

    if connect_timeout <= 0 or read_timeout <= 0:
        raise ValueError("banner timeouts must be positive")
    if not 1 <= max_bytes <= 65536:
        raise ValueError("banner max_bytes must be between 1 and 65536")
    address = ipaddress.ip_address(host)
    family = socket.AF_INET if address.version == 4 else socket.AF_INET6
    endpoint = (str(address), port) if family == socket.AF_INET else (str(address), port, 0, 0)
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(connect_timeout)
            sock.connect(endpoint)
            sock.settimeout(read_timeout)
            data = sock.recv(max_bytes + 1)
    except socket.timeout:
        return _result("timeout", error="timeout")
    except OSError:
        return _result("error", error="connection_error")
    if not data:
        return _result("empty")
    return _result("collected", data=data[:max_bytes], truncated=len(data) > max_bytes)


def collect_open_banners(host_results: Mapping[str, Sequence[Mapping[str, Any]]], *, workers: int = DEFAULT_BANNER_WORKERS, max_endpoints: int = DEFAULT_MAX_ENDPOINTS, connect_timeout: float = 0.5, read_timeout: float = 0.5, max_bytes: int = DEFAULT_MAX_BYTES) -> dict[str, list[dict[str, Any]]]:
    """Return copied observations enriched for a bounded prefix of open endpoints."""

    if not 1 <= workers <= MAX_BANNER_WORKERS or max_endpoints < 1:
        raise ValueError("invalid banner concurrency limit")
    copied = {host: [dict(item) for item in items] for host, items in host_results.items()}
    eligible = [(host, item) for host, items in copied.items() for item in items if item.get("state") == "open"]
    selected = eligible[:max_endpoints]
    for _, item in eligible[max_endpoints:]:
        item["banner"] = _result("skipped", error="endpoint_limit")
    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(selected)))) as executor:
        futures = [executor.submit(collect_banner, host, int(item["port"]), connect_timeout=connect_timeout, read_timeout=read_timeout, max_bytes=max_bytes) for host, item in selected]
        for (_, item), future in zip(selected, futures):
            try:
                item["banner"] = future.result()
            except Exception:
                item["banner"] = _result("error", error="worker_error")
    return copied
