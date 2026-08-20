"""Stable, deterministic discovery evidence records."""

from __future__ import annotations

import hashlib
import ipaddress
from collections.abc import Mapping
from typing import Any

RESULTS = {"response", "no_response", "timeout", "probe_error", "unsupported"}


def discovery_observation(address: object, result: str, *, method: str = "icmp_echo", error_code: str | None = None) -> dict[str, Any]:
    canonical = str(ipaddress.ip_address(str(address)))
    if result not in RESULTS:
        raise ValueError(f"unsupported discovery result: {result}")
    material = f"{canonical}\0{method}\0{result}\0{error_code or ''}".encode("ascii")
    value: dict[str, Any] = {
        "discovery_observation_id": "discovery_" + hashlib.sha256(material).hexdigest()[:24],
        "address": canonical,
        "ip_version": ipaddress.ip_address(canonical).version,
        "method": method,
        "result": result,
    }
    if error_code is not None:
        value["error"] = {"code": error_code}
    return value


def discovery_summary(observations: list[Mapping[str, Any]]) -> dict[str, Any]:
    return {
        "observations": len(observations),
        "results": {result: sum(item.get("result") == result for item in observations) for result in sorted(RESULTS)},
    }
