"""Safe, bounded HTTP metadata evidence without navigation or authentication."""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
from collections.abc import Mapping, Sequence
from typing import Any

from scanner.pipeline import execute_bounded_phase

MAX_HTTP_WORKERS = 16
DEFAULT_HTTP_PORTS = (80, 443)
DEFAULT_HTTPS_PORTS = frozenset({443, 8443})
ALLOWLISTED_HEADERS = frozenset({"content-type", "content-length", "location", "server", "date"})


def _result(status: str, *, method: str, error: str | None = None) -> dict[str, Any]:
    value: dict[str, Any] = {
        "status": status, "method": method, "request_target": "/",
        "redirect_followed": False, "authenticated": False, "trusted": False,
    }
    if error:
        value["error"] = {"code": error}
    return value


def _host_literal(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    return str(address) if address.version == 4 else f"[{address}]"


def _read_headers(sock: socket.socket, *, max_header_bytes: int, max_header_line: int, max_header_count: int) -> tuple[bytes, bytes]:
    buffer = bytearray()
    while b"\r\n\r\n" not in buffer:
        if len(buffer) >= max_header_bytes:
            raise ValueError("header_bytes_limit")
        chunk = sock.recv(min(4096, max_header_bytes + 1 - len(buffer)))
        if not chunk:
            raise ValueError("incomplete_headers")
        buffer.extend(chunk)
    head, body = bytes(buffer).split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    if any(len(line) > max_header_line for line in lines) or len(lines) - 1 > max_header_count:
        raise ValueError("header_structure_limit")
    return head, body


def _parse_headers(head: bytes) -> tuple[str, int, dict[str, str]]:
    lines = head.split(b"\r\n")
    try:
        status_line = lines[0].decode("ascii")
        version, status_text, _ = status_line.split(" ", 2)
        if version not in {"HTTP/1.0", "HTTP/1.1"}:
            raise ValueError
        status = int(status_text)
        if not 100 <= status <= 999:
            raise ValueError
    except (UnicodeError, ValueError):
        raise ValueError("invalid_status_line") from None
    headers: dict[str, str] = {}
    for raw in lines[1:]:
        if b":" not in raw:
            raise ValueError("invalid_header")
        name, value = raw.split(b":", 1)
        try:
            key = name.decode("ascii").strip().lower()
            text = value.decode("iso-8859-1").strip()
        except UnicodeError:
            raise ValueError("invalid_header") from None
        if key in ALLOWLISTED_HEADERS and key not in headers:
            headers[key] = text
    return version.removeprefix("HTTP/"), status, dict(sorted(headers.items()))


def _read_prefix(sock: socket.socket, initial: bytes, limit: int) -> tuple[bytes, bool]:
    data = bytearray(initial[: limit + 1])
    while len(data) <= limit:
        chunk = sock.recv(min(4096, limit + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data[:limit]), len(data) > limit


def _single_request(
    address: object,
    port: int,
    method: str,
    *,
    use_tls: bool,
    connect_timeout: float,
    tls_timeout: float,
    read_timeout: float,
    max_header_bytes: int,
    max_header_line: int,
    max_header_count: int,
    body_hash_bytes: int,
) -> dict[str, Any]:
    ip = ipaddress.ip_address(str(address))
    family = socket.AF_INET if ip.version == 4 else socket.AF_INET6
    endpoint = (str(ip), port) if ip.version == 4 else (str(ip), port, 0, 0)
    raw: socket.socket | None = None
    stream: socket.socket | ssl.SSLSocket | None = None
    try:
        raw = socket.socket(family, socket.SOCK_STREAM)
        raw.settimeout(connect_timeout)
        raw.connect(endpoint)
        stream = raw
        if use_tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False; context.verify_mode = ssl.CERT_NONE
            raw.settimeout(tls_timeout)
            stream = context.wrap_socket(raw, server_hostname=None)
        stream.settimeout(read_timeout)
        lines = [f"{method} / HTTP/1.1", f"Host: {_host_literal(ip)}", "Connection: close", "User-Agent: PROJECT-SCAN/2.1"]
        if method == "GET":
            lines.append(f"Range: bytes=0-{max(0, body_hash_bytes - 1)}")
        request = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")
        stream.sendall(request)
        head, initial = _read_headers(stream, max_header_bytes=max_header_bytes, max_header_line=max_header_line, max_header_count=max_header_count)
        version, status_code, headers = _parse_headers(head)
        value = _result("collected", method=method)
        value.update({"status_code": status_code, "http_version": version, "headers": headers, "bytes_read": 0, "truncated": False})
        for source, target in (("content-type", "content_type"), ("location", "location"), ("server", "server_hint")):
            if source in headers: value[target] = headers[source]
        if "content-length" in headers:
            try:
                declared = int(headers["content-length"])
                if declared >= 0: value["declared_content_length"] = declared
            except ValueError:
                value["declared_content_length_invalid"] = True
        if method == "GET" and body_hash_bytes > 0:
            body, truncated = _read_prefix(stream, initial, body_hash_bytes)
            value["bytes_read"] = len(body); value["truncated"] = truncated
            if body: value["body_prefix_sha256"] = hashlib.sha256(body).hexdigest()
        return value
    except socket.timeout:
        return _result("timeout", method=method, error="timeout")
    except ssl.SSLError:
        return _result("error", method=method, error="tls_error")
    except ValueError as exc:
        return _result("error", method=method, error=str(exc))
    except OSError:
        return _result("error", method=method, error="connection_error")
    finally:
        if stream is not None:
            stream.close()
        elif raw is not None:
            raw.close()


def collect_http_metadata(address: object, port: int, *, method_mode: str = "head", use_tls: bool | None = None, connect_timeout: float = .5, tls_timeout: float = 1.0, read_timeout: float = 1.0, max_header_bytes: int = 16384, max_header_line: int = 4096, max_header_count: int = 64, body_hash_bytes: int = 4096) -> dict[str, Any]:
    """Collect allowlisted metadata; redirects are returned and never followed."""
    if method_mode not in {"head", "head-get"} or min(connect_timeout, tls_timeout, read_timeout) <= 0 or not 512 <= max_header_bytes <= 65536 or not 128 <= max_header_line <= max_header_bytes or not 1 <= max_header_count <= 256 or not 0 <= body_hash_bytes <= 65536:
        raise ValueError("invalid HTTP limits")
    tls = port in DEFAULT_HTTPS_PORTS if use_tls is None else use_tls
    options = dict(use_tls=tls, connect_timeout=connect_timeout, tls_timeout=tls_timeout, read_timeout=read_timeout, max_header_bytes=max_header_bytes, max_header_line=max_header_line, max_header_count=max_header_count, body_hash_bytes=body_hash_bytes)
    head = _single_request(address, port, "HEAD", **options)
    if method_mode == "head-get" and head.get("status_code") in {405, 501}:
        return _single_request(address, port, "GET", **options)
    return head


def collect_open_http(host_results: Mapping[str, Sequence[Mapping[str, Any]]], *, ports: Sequence[int] = DEFAULT_HTTP_PORTS, workers: int = 4, max_endpoints: int = 32, method_mode: str = "head", connect_timeout: float = .5, tls_timeout: float = 1.0, read_timeout: float = 1.0, max_header_bytes: int = 16384, max_header_line: int = 4096, max_header_count: int = 64, body_hash_bytes: int = 4096) -> dict[str, list[dict[str, Any]]]:
    if not 1 <= workers <= MAX_HTTP_WORKERS or max_endpoints < 1:
        raise ValueError("invalid HTTP concurrency limits")
    allowed = set(ports)
    copied = {host: [dict(item) for item in items] for host, items in host_results.items()}
    eligible = [(host, item) for host, items in copied.items() for item in items if item.get("state") == "open" and int(item["port"]) in allowed]
    arguments = [(host, int(item["port"])) for host, item in eligible]
    def run(host: str, port: int) -> dict[str, Any]:
        return collect_http_metadata(host, port, method_mode=method_mode, connect_timeout=connect_timeout, tls_timeout=tls_timeout, read_timeout=read_timeout, max_header_bytes=max_header_bytes, max_header_line=max_header_line, max_header_count=max_header_count, body_hash_bytes=body_hash_bytes)
    values, omitted = execute_bounded_phase(run, arguments, workers=workers, max_records=max_endpoints)
    for (_, item), value in zip(eligible, values):
        item["http"] = _result("error", method="HEAD", error="worker_error") if isinstance(value, Exception) else value
    for _, item in eligible[len(values):]:
        item["http"] = _result("skipped", method="HEAD", error="endpoint_limit")
    assert omitted == max(0, len(eligible) - len(values))
    return copied
