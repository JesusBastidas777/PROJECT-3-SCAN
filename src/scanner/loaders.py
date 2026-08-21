"""Bounded, version-aware local contract loaders."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scanner.contract import validate_report_shape
from scanner.snapshots import validate_snapshot

DEFAULT_MAX_INPUT_BYTES = 16 * 1024 * 1024


def load_json_document(path: Path, *, max_bytes: int = DEFAULT_MAX_INPUT_BYTES, allow_symlink: bool = False) -> dict[str, Any]:
    supplied = Path(path)
    if not allow_symlink and supplied.is_symlink():
        raise OSError("input path cannot be a symlink")
    if max_bytes < 1 or supplied.stat().st_size > max_bytes:
        raise OSError("input exceeds size limit")
    value = json.loads(supplied.read_text(encoding="utf-8", errors="strict"))
    if not isinstance(value, dict):
        raise ValueError("input must be one JSON object")
    return value


def load_report(path: Path, *, max_bytes: int = DEFAULT_MAX_INPUT_BYTES) -> dict[str, Any]:
    value = load_json_document(path, max_bytes=max_bytes)
    validate_report_shape(value)
    return value


def load_snapshot(path: Path, *, max_bytes: int = DEFAULT_MAX_INPUT_BYTES) -> dict[str, Any]:
    value = load_json_document(path, max_bytes=max_bytes)
    validate_snapshot(value)
    return value


def load_report_or_snapshot(path: Path, *, max_bytes: int = DEFAULT_MAX_INPUT_BYTES) -> tuple[dict[str, Any], dict[str, Any] | None]:
    value = load_json_document(path, max_bytes=max_bytes)
    if "report" in value and "snapshot_id" in value:
        validate_snapshot(value)
        return dict(value["report"]), value
    validate_report_shape(value)
    return value, None
