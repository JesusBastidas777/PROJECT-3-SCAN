"""Normalized per-scan asset inventory with scoped observation identities."""

from __future__ import annotations

import hashlib
import ipaddress
from collections.abc import Mapping, Sequence
from typing import Any

from scanner.fingerprint import fingerprint_host


def target_id(target: object) -> str:
    canonical = str(ipaddress.ip_network(str(target), strict=False))
    return "target_" + hashlib.sha256(canonical.encode("ascii")).hexdigest()[:20]


def asset_id(target: object, address: object) -> str:
    """Return an observation identity scoped to one canonical target and address."""

    canonical_address = str(ipaddress.ip_address(str(address)))
    material = f"{target_id(target)}\0{canonical_address}".encode("ascii")
    return "asset_" + hashlib.sha256(material).hexdigest()[:20]


def build_inventory(target: object, host_results: Mapping[str, Sequence[Mapping[str, Any]]]) -> list[dict[str, Any]]:
    """Build deterministic assets without merging distinct addresses."""

    canonical_target = str(ipaddress.ip_network(str(target), strict=False))
    normalized: dict[str, Sequence[Mapping[str, Any]]] = {}
    for host, observations in host_results.items():
        normalized[str(ipaddress.ip_address(host))] = observations
    assets = []
    for host in sorted(normalized, key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value)))):
        endpoints_by_key: dict[tuple[str, int], dict[str, Any]] = {}
        for observation in normalized[host]:
            endpoint = dict(observation)
            key = (str(endpoint.get("transport", "tcp")), int(endpoint["port"]))
            endpoints_by_key[key] = endpoint
        endpoints = [endpoints_by_key[key] for key in sorted(endpoints_by_key)]
        assets.append({
            "asset_id": asset_id(canonical_target, host),
            "addresses": [{"address": host, "ip_version": ipaddress.ip_address(host).version}],
            "identity": {"scope": target_id(canonical_target), "basis": "target_and_address_observation", "physical_device": False},
            "endpoints": endpoints,
            "fingerprints": fingerprint_host(host, endpoints),
        })
    return assets
