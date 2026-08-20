"""ICMP host reachability helpers."""

from __future__ import annotations

import ipaddress
import math
import subprocess


def ping_host(ip: object, timeout: float = 1.0) -> bool:
    """Return whether *ip* answers one ICMP echo request.

    Operational failures are treated as an unreachable host so that one failed
    probe cannot abort discovery.  ``KeyboardInterrupt`` is intentionally not
    swallowed; the CLI handles it as a user cancellation.
    """

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
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False

    return result.returncode == 0
