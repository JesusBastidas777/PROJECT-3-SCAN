"""Construction and legacy projection of normalized TCP observations."""

from __future__ import annotations

from typing import Any

from scanner.services import service_hint


def tcp_observation(port: int, state: str, result: str, *, error_code: str | None = None) -> dict[str, Any]:
    """Build one deterministic TCP-connect observation."""

    if state not in {"open", "closed", "unknown", "error"}:
        raise ValueError(f"unsupported TCP state: {state}")
    observation: dict[str, Any] = {
        "port": port,
        "transport": "tcp",
        "state": state,
        "state_evidence": {"method": "tcp_connect", "result": result},
    }
    hint = service_hint(port)
    if hint is not None:
        observation["service"] = hint
    if error_code is not None:
        observation["error"] = {"code": error_code}
    return observation


def legacy_port_result(observation: dict[str, Any]) -> dict[str, object]:
    """Project a rich observation to the frozen schema-1.0 port shape."""

    return {
        "port": observation["port"],
        "protocol": "tcp",
        "status": "OPEN" if observation["state"] == "open" else "CLOSED",
    }
