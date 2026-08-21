"""Bounded, deterministic phase execution helpers."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from scanner.concurrency import bounded_ordered_calls


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
