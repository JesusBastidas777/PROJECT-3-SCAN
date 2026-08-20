"""Pure, transparent and weak host fingerprint rules."""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from typing import Any

RULESET_VERSION = "1.0"


def fingerprint_host(host: str, observations: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Derive low-confidence attributes solely from supplied evidence."""

    address = ipaddress.ip_address(host)
    fingerprints: list[dict[str, Any]] = [{
        "attribute": "ip_family", "value": f"ipv{address.version}",
        "confidence": "observed", "basis": [f"address:{address}"],
        "rule_id": "ip-family-v1",
    }]
    open_items = [item for item in observations if item.get("state") == "open"]
    families: dict[str, list[str]] = {}
    family_by_hint = {
        "http": "web", "https": "web", "ssh": "remote_access",
        "telnet": "remote_access", "smtp": "messaging", "imap": "messaging",
        "pop3": "messaging", "microsoft-ds": "file_sharing",
    }
    for item in open_items:
        service = item.get("service")
        if not isinstance(service, Mapping) or service.get("confidence") != "hint":
            continue
        family = family_by_hint.get(str(service.get("name")))
        if family:
            families.setdefault(family, []).append(f"tcp/{int(item['port'])}:port_registry_hint")
    for family in sorted(families):
        fingerprints.append({
            "attribute": "service_family", "value": family,
            "confidence": "low", "basis": sorted(families[family]),
            "rule_id": f"service-family-{family}-v1",
        })
    return fingerprints


def fingerprint_hosts(host_results: Mapping[str, Sequence[Mapping[str, Any]]]) -> dict[str, list[dict[str, Any]]]:
    """Fingerprint hosts in canonical address order."""

    return {host: fingerprint_host(host, host_results[host]) for host in sorted(host_results, key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value))))}
