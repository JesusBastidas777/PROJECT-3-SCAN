"""Small, dependency-free contracts shared by evidence probes."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


class EvidenceProbe(Protocol):
    """A bounded probe that returns structured evidence and never prints."""

    capability_id: str

    def __call__(self, *arguments: Any) -> Any: ...


@dataclass(frozen=True)
class ProbeLimits:
    """Effective operational limits recorded with a phase."""

    workers: int = 0
    timeout_seconds: float | None = None
    max_records: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {"workers": self.workers}
        if self.timeout_seconds is not None:
            value["timeout_seconds"] = self.timeout_seconds
        if self.max_records is not None:
            value["max_records"] = self.max_records
        value.update(self.extra)
        return value
