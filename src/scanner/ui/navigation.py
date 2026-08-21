"""Bounded view selection."""

from scanner.ui import VIEWS


def normalize_view(value: str) -> str:
    normalized = str(value).strip().lower()
    if normalized not in VIEWS:
        raise ValueError("unknown SCAN UI view")
    return normalized
