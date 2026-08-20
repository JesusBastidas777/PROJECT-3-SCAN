"""ICMP host reachability helpers."""

from __future__ import annotations

import ipaddress
import math
import subprocess

from scanner.discovery_evidence import discovery_observation


def ping_host(ip: object, timeout: float = 1.0) -> bool:
    """Return whether *ip* answers one ICMP echo request.

    Operational failures are treated as an unreachable host so that one failed
    probe cannot abort discovery.  ``KeyboardInterrupt`` is intentionally not
    swallowed; the CLI handles it as a user cancellation.
    """

    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        raise ValueError("ping timeout must be a positive number")

    return ping_evidence(ip, timeout)["result"] == "response"


def ping_evidence(ip: object, timeout: float = 1.0) -> dict[str, object]:
    """Return stable ICMP evidence without retaining platform output."""

    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        raise ValueError("ping timeout must be a positive number")
    address = ipaddress.ip_address(str(ip))
    command = ["ping"]
    if address.version == 6:
        command.append("-6")
    command.extend(
        ["-c", "1", "-W", str(max(1, math.ceil(timeout))), str(address)]
    )

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 0.5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return discovery_observation(address, "timeout", error_code="timeout")
    except FileNotFoundError:
        return discovery_observation(address, "unsupported", error_code="ping_unavailable")
    except OSError:
        return discovery_observation(address, "probe_error", error_code="process_error")
    return discovery_observation(address, "response" if result.returncode == 0 else "no_response")
