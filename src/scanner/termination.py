"""Stable execution termination reason codes."""
from dataclasses import dataclass
from typing import Optional
REASONS=frozenset({"budget_exhausted","operator_interrupted","operational_failure","probe_timeout","probe_error","excluded_by_policy","dependency_not_observed"})
@dataclass(frozen=True)
class Termination:
    reason_code: str; phase: str; budget_id: str|None=None; occurred_at: str|None=None
    def __post_init__(self):
        if self.reason_code not in REASONS: raise ValueError("invalid termination reason")
