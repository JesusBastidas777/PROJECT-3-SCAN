"""Passive, bounded evidence from existing local neighbor tables."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path
import platform
import subprocess
from collections.abc import Mapping, Sequence
from typing import Any

from scanner.contract import semantic_hash
from scanner.platform_context import network_context


def _canonical_mac(value: str) -> str:
    compact = value.strip().lower().replace("-", ":")
    parts = compact.split(":")
    if len(parts) != 6 or any(len(part) != 2 or any(char not in "0123456789abcdef" for char in part) for part in parts):
        raise ValueError("invalid link-layer address")
    return ":".join(parts)


class NeighborBackend:
    name = "abstract"

    def read(self, timeout: float) -> list[dict[str, Any]]:
        raise NotImplementedError


class LinuxIpNeighborBackend(NeighborBackend):
    name = "linux_ip_json"

    def read(self, timeout: float) -> list[dict[str, Any]]:
        result = subprocess.run(
            ["ip", "-j", "neighbor", "show"], capture_output=True, text=True,
            encoding="utf-8", errors="strict", timeout=timeout, check=False,
            shell=False,
        )
        if result.returncode != 0:
            raise OSError("neighbor_command_failed")
        value = json.loads(result.stdout)
        if not isinstance(value, list):
            raise ValueError("invalid neighbor JSON")
        output = []
        for item in value:
            if not isinstance(item, Mapping) or not isinstance(item.get("dst"), str) or not isinstance(item.get("dev"), str):
                continue
            output.append({"address": item["dst"], "interface": item["dev"], "link_layer_address": item.get("lladdr"), "neighbor_state": str(item.get("state", "unknown")).lower()})
        return output


class LinuxProcArpBackend(NeighborBackend):
    name = "linux_proc_arp"

    def __init__(self, path: Path = Path("/proc/net/arp")) -> None:
        self.path = path

    def read(self, timeout: float) -> list[dict[str, Any]]:
        del timeout
        lines = self.path.read_text(encoding="ascii").splitlines()
        output = []
        for line in lines[1:]:
            fields = line.split()
            if len(fields) >= 6:
                output.append({"address": fields[0], "link_layer_address": fields[3], "interface": fields[5], "neighbor_state": "cached"})
        return output


class WindowsPowerShellNeighborBackend(NeighborBackend):
    name = "windows_powershell"
    COMMAND = [
        "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
        "Get-NetNeighbor | Select-Object IPAddress,LinkLayerAddress,InterfaceAlias,State | ConvertTo-Json -Compress",
    ]

    def read(self, timeout: float) -> list[dict[str, Any]]:
        result = subprocess.run(self.COMMAND, capture_output=True, text=True, encoding="utf-8", errors="strict", timeout=timeout, check=False, shell=False)
        if result.returncode != 0:
            raise OSError("neighbor_command_failed")
        raw = json.loads(result.stdout or "[]")
        values = raw if isinstance(raw, list) else [raw]
        return [
            {"address": item.get("IPAddress"), "link_layer_address": item.get("LinkLayerAddress"), "interface": item.get("InterfaceAlias"), "neighbor_state": str(item.get("State", "unknown")).lower()}
            for item in values if isinstance(item, Mapping)
        ]


class UnsupportedNeighborBackend(NeighborBackend):
    name = "unsupported"

    def read(self, timeout: float) -> list[dict[str, Any]]:
        del timeout
        raise NotImplementedError("neighbor_backend_unavailable")


def select_backend(*, system: str | None = None) -> NeighborBackend:
    name = (system or platform.system()).lower()
    if name == "windows":
        return WindowsPowerShellNeighborBackend()
    if name == "linux":
        return LinuxIpNeighborBackend()
    return UnsupportedNeighborBackend()


def _eligible_network(target: object) -> bool:
    network = ipaddress.ip_network(str(target), strict=False)
    address = network.network_address
    return not (address.is_loopback or address.is_multicast or address.is_unspecified) and (address.is_private or address.is_link_local)


def collect_neighbor_evidence(
    target: object,
    *,
    backend: NeighborBackend | None = None,
    privacy: str = "hash-only",
    max_records: int = 256,
    timeout: float = 1.0,
    interface: str | None = None,
    context: str | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Read and filter a system table; never sends neighbor discovery traffic."""

    if privacy not in {"hash-only", "full"} or max_records < 1 or timeout <= 0:
        raise ValueError("invalid neighbor collection limits")
    selected_backend = backend or select_backend()
    runtime_context = context or network_context()
    limits = {"workers": 0, "timeout_seconds": timeout, "max_records": max_records, "interface": interface}
    if not _eligible_network(target):
        return [], {"supported": True, "backend": selected_backend.name, "reason": "target_not_on_link", "eligible": 0, "attempted": 0, "truncated": False, "limits": limits}
    try:
        raw = selected_backend.read(timeout)
    except NotImplementedError:
        return [], {"supported": False, "backend": selected_backend.name, "reason": "backend_unavailable", "eligible": 0, "attempted": 0, "truncated": False, "limits": limits}
    except subprocess.TimeoutExpired:
        return [], {"supported": True, "backend": selected_backend.name, "reason": "timeout", "eligible": 1, "attempted": 1, "timeout": 1, "truncated": False, "limits": limits}
    except PermissionError:
        return [], {"supported": False, "backend": selected_backend.name, "reason": "permission_denied", "eligible": 0, "attempted": 0, "truncated": False, "limits": limits}
    except (OSError, ValueError, json.JSONDecodeError, UnicodeError):
        if isinstance(selected_backend, LinuxIpNeighborBackend):
            try:
                return collect_neighbor_evidence(target, backend=LinuxProcArpBackend(), privacy=privacy, max_records=max_records, timeout=timeout, interface=interface, context=runtime_context)
            except OSError:
                pass
        return [], {"supported": True, "backend": selected_backend.name, "reason": "backend_error", "eligible": 1, "attempted": 1, "error": 1, "truncated": False, "limits": limits}
    network = ipaddress.ip_network(str(target), strict=False)
    normalized = []
    for item in raw:
        try:
            address = ipaddress.ip_address(str(item.get("address")))
        except ValueError:
            continue
        if address not in network or address.is_loopback or address.is_multicast or address.is_unspecified:
            continue
        if interface and item.get("interface") != interface:
            continue
        link = item.get("link_layer_address")
        try:
            link = _canonical_mac(str(link)) if link else None
        except ValueError:
            link = None
        base: dict[str, Any] = {
            "address": str(address), "ip_version": address.version,
            "interface": str(item.get("interface")), "neighbor_state": str(item.get("neighbor_state", "unknown")),
            "source": "system_neighbor_table", "backend": selected_backend.name,
            "network_context": runtime_context, "active_probe": False, "trusted": False,
            "scope": "local_link", "limitations": ["cache_entry_does_not_prove_current_reachability", "link_layer_address_does_not_prove_physical_identity"],
        }
        if link:
            base["link_layer_sha256"] = hashlib.sha256(link.encode("ascii")).hexdigest()
            if privacy == "full":
                base["link_layer_address"] = link
        base["neighbor_observation_id"] = "neighbor_" + semantic_hash(base)[:24]
        normalized.append(base)
    normalized.sort(key=lambda item: (item["ip_version"], int(ipaddress.ip_address(item["address"])), item["interface"]))
    eligible = len(normalized)
    output = normalized[:max_records]
    return output, {"supported": True, "backend": selected_backend.name, "eligible": eligible, "attempted": eligible, "observed": len(output), "skipped": max(0, eligible - len(output)), "truncated": eligible > len(output), "limits": limits}
