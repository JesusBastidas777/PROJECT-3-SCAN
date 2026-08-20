"""Optional, bounded TLS handshake metadata collection."""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
from collections.abc import Mapping, Sequence
from typing import Any

from scanner.concurrency import bounded_ordered_calls

MAX_TLS_WORKERS = 16
DEFAULT_TLS_PORTS = (443,)


def _result(status: str, *, error: str | None = None) -> dict[str, Any]:
    value: dict[str, Any] = {"status": status, "method": "tls_handshake", "trusted": False, "validation_performed": False}
    if error:
        value["error"] = {"code": error}
    return value


def collect_tls_metadata(address: object, port: int, connect_timeout: float, handshake_timeout: float) -> dict[str, Any]:
    """Perform one TLS handshake without SNI, authentication or application data."""

    if connect_timeout <= 0 or handshake_timeout <= 0:
        raise ValueError("TLS timeouts must be positive")
    ip = ipaddress.ip_address(str(address))
    family = socket.AF_INET if ip.version == 4 else socket.AF_INET6
    endpoint = (str(ip), port) if family == socket.AF_INET else (str(ip), port, 0, 0)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.socket(family, socket.SOCK_STREAM) as raw:
            raw.settimeout(connect_timeout)
            raw.connect(endpoint)
            raw.settimeout(handshake_timeout)
            with context.wrap_socket(raw, server_hostname=None, do_handshake_on_connect=False) as secured:
                secured.do_handshake()
                value = _result("collected")
                value["protocol"] = secured.version()
                cipher = secured.cipher()
                if cipher:
                    value["cipher"] = {"name": cipher[0], "protocol": cipher[1], "bits": cipher[2]}
                certificate = secured.getpeercert(binary_form=True)
                if certificate:
                    value["certificate_sha256"] = hashlib.sha256(certificate).hexdigest()
                    value["certificate_representation"] = "hash_only"
                return value
    except (socket.timeout, TimeoutError):
        return _result("timeout", error="timeout")
    except ssl.SSLError:
        return _result("handshake_failed", error="tls_handshake_error")
    except OSError:
        return _result("error", error="connection_error")


def collect_open_tls(host_results: Mapping[str, Sequence[Mapping[str, Any]]], *, ports: Sequence[int] = DEFAULT_TLS_PORTS, workers: int = 4, max_endpoints: int = 32, connect_timeout: float = .5, handshake_timeout: float = 1.0) -> dict[str, list[dict[str, Any]]]:
    if not 1 <= workers <= MAX_TLS_WORKERS or max_endpoints < 1:
        raise ValueError("invalid TLS limits")
    allowed = set(ports)
    copied = {host: [dict(item) for item in items] for host, items in host_results.items()}
    eligible = [(host, item) for host, items in copied.items() for item in items if item.get("state") == "open" and int(item["port"]) in allowed]
    selected = eligible[:max_endpoints]
    for _, item in eligible[max_endpoints:]:
        item["tls"] = _result("skipped", error="endpoint_limit")
    tasks = [(host, int(item["port"]), connect_timeout, handshake_timeout) for host, item in selected]
    values = bounded_ordered_calls(collect_tls_metadata, tasks, max_workers=min(workers, max(1, len(tasks)))) if tasks else []
    for (_, item), value in zip(selected, values):
        item["tls"] = _result("error", error="worker_error") if isinstance(value, Exception) else value
    return copied
