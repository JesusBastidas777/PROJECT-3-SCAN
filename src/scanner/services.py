"""Conservative conventional service hints with no protocol claims."""

from __future__ import annotations


_TCP_SERVICE_HINTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "microsoft-ds",
    3389: "ms-wbt-server",
}


def service_hint(port: int, transport: str = "tcp") -> dict[str, str] | None:
    """Return a registry hint; the result never confirms the actual protocol."""

    name = _TCP_SERVICE_HINTS.get(port) if transport == "tcp" else None
    if name is None:
        return None
    return {"name": name, "basis": "port_registry", "confidence": "hint"}
