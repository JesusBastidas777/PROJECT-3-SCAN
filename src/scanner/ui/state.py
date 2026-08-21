"""Immutable state passed to pure UI renderers."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True)
class UIState:
    view: str = "overview"
    payload: Any = None
    status: str = "unknown"
    updated_at: str | None = None
    stale: bool = False
    error: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
