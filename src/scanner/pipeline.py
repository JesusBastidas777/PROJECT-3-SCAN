"""Bounded, deterministic phase execution helpers."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from scanner.concurrency import bounded_ordered_calls
from scanner.configuration import ResolvedScanConfiguration
def execute_scan(configuration: ResolvedScanConfiguration) -> dict[str, Any]:
    """Lazily enter the acquisition coordinator to avoid phase import cycles."""
    from scanner.scan_pipeline import execute_scan as run
    return run(configuration)

def build_scan_plan(configuration: ResolvedScanConfiguration) -> ResolvedScanConfiguration:
    """Return the resolved acquisition intent; DAY#59 adds its public projection."""
    return configuration

def build_report(execution_result: dict[str, Any]) -> dict[str, Any]:
    """Reports are currently the terminal immutable execution result."""
    return execution_result


def execute_bounded_phase(
    function: Callable[..., Any],
    arguments: Sequence[tuple[Any, ...]],
    *,
    workers: int,
    max_records: int,
) -> tuple[list[Any], int]:
    """Execute a deterministic prefix and return values plus omitted count."""

    if workers < 1 or max_records < 0:
        raise ValueError("invalid bounded phase limits")
    selected = list(arguments[:max_records])
    omitted = max(0, len(arguments) - len(selected))
    if not selected:
        return [], omitted
    return (
        bounded_ordered_calls(
            function,
            selected,
            max_workers=min(workers, len(selected)),
        ),
        omitted,
    )
