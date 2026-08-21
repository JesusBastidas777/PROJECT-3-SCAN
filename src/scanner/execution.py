"""Typed terminal result of one SCAN acquisition execution."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any

@dataclass(frozen=True)
class ScanExecutionResult:
    report: dict[str, Any]
