"""Stable public models for SCAN consumers such as FOREX."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
import json
from pathlib import Path
from typing import Any, Mapping


def _primitive(value: Any) -> Any:
    if is_dataclass(value):
        return _primitive(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _primitive(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_primitive(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    return value


@dataclass(frozen=True)
class SCANConfig:
    """Explicit locations used by the read-only public facade."""

    reports_dir: Path
    history_dir: Path | None = None
    outbox_dir: Path | None = None


@dataclass(frozen=True)
class SCANResponseV1:
    """Versioned deterministic response returned by every public operation."""

    status: str = "success"
    data: Any = field(default_factory=dict)
    errors: tuple[Mapping[str, Any], ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)
    schema_version: str = "1.0"

    def __post_init__(self) -> None:
        if self.status not in {"success", "degraded"}:
            raise ValueError("SCAN response status must be success or degraded")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "status": self.status,
            "data": _primitive(self.data),
            "errors": _primitive(self.errors),
            "metadata": _primitive(self.metadata),
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(), ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        )
