"""Bounded-submission executor helpers."""
from __future__ import annotations
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from collections.abc import Callable, Sequence
from typing import Any

def bounded_ordered_calls(function: Callable[..., Any], arguments: Sequence[tuple[Any, ...]], *, max_workers: int, max_pending: int | None = None) -> list[Any]:
    """Run bounded calls and return input-order values or isolated exceptions."""
    if max_workers < 1:
        raise ValueError("max_workers must be positive")
    limit = max_pending or max_workers * 2
    if limit < max_workers:
        raise ValueError("max_pending cannot be smaller than max_workers")
    results: list[Any] = [None] * len(arguments)
    next_index = 0
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        pending = {}
        while next_index < len(arguments) and len(pending) < limit:
            pending[executor.submit(function, *arguments[next_index])] = next_index
            next_index += 1
        while pending:
            done, _ = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                index = pending.pop(future)
                try:
                    results[index] = future.result()
                except KeyboardInterrupt:
                    raise
                except Exception as exc:
                    results[index] = exc
                if next_index < len(arguments):
                    pending[executor.submit(function, *arguments[next_index])] = next_index
                    next_index += 1
    return results
