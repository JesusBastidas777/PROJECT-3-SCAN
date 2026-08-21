"""Explicit SCAN runtime and job state machines."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


RUNTIME_STATES = {"starting", "idle", "stopped", "crashed"}
JOB_STATES = {"planning", "running", "checkpointing", "cancelling", "completed", "partial", "failed"}
TERMINAL_JOB_STATES = {"completed", "partial", "failed"}
JOB_TRANSITIONS = {
    None: {"planning"},
    "planning": {"running", "failed", "cancelling"},
    "running": {"checkpointing", "cancelling", "completed", "partial", "failed"},
    "checkpointing": {"running", "cancelling", "partial", "failed"},
    "cancelling": {"partial", "completed", "failed"},
    "completed": set(), "partial": set(), "failed": set(),
}


@dataclass
class JobState:
    scan_id: str
    target: str
    state: str = "planning"
    partial: bool = False
    errors: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.state not in JOB_STATES:
            raise ValueError("invalid initial job state")

    def transition(self, state: str) -> None:
        if state not in JOB_TRANSITIONS.get(self.state, set()):
            raise ValueError(f"invalid job transition: {self.state} -> {state}")
        self.state = state
        self.partial = state == "partial"
