"""Immutable, opt-in JSON snapshot storage."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from collections.abc import Mapping
from typing import Any

from scanner.contract import canonical_content, semantic_hash, validate_report_shape
from scanner.locking import FileLock


def build_snapshot(report: Mapping[str, Any], previous_snapshot_id: str | None = None) -> dict[str, Any]:
    validate_report_shape(report)
    if report["schema_version"] != "2.0":
        raise ValueError("snapshots require report schema 2.0")
    configuration_fingerprint = semantic_hash(report["configuration"])
    content_fingerprint = semantic_hash(canonical_content(report))
    snapshot_id = "snapshot_" + semantic_hash({"scan_id": report["scan_id"], "content": content_fingerprint})[:24]
    value = {
        "snapshot_id": snapshot_id, "scan_id": report["scan_id"],
        "target_id": report["target"]["target_id"],
        "configuration_fingerprint": configuration_fingerprint,
        "content_fingerprint": content_fingerprint, "report": dict(report),
    }
    if previous_snapshot_id:
        value["previous_snapshot_id"] = previous_snapshot_id
    return value


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False) as handle:
            temporary = Path(handle.name)
            json.dump(value, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def save_snapshot(report: Mapping[str, Any], root: Path, *, lock_timeout: float = 5.0) -> tuple[dict[str, Any], Path]:
    """Persist an immutable snapshot and atomically update its small index."""

    supplied_root = Path(root)
    if supplied_root.exists() and supplied_root.is_symlink():
        raise OSError("snapshot root cannot be a symlink")
    root = supplied_root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    with FileLock(root / ".scan-history.lock", timeout=lock_timeout):
        return _save_snapshot_locked(report, root)


def _save_snapshot_locked(report: Mapping[str, Any], root: Path) -> tuple[dict[str, Any], Path]:
    index_path = root / "index.json"
    if index_path.exists():
        try:
            index = json.loads(index_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise OSError("snapshot index is corrupt") from exc
    else:
        index = {"version": "1.0", "targets": {}}
    target = report.get("target", {}).get("target_id")
    if not isinstance(target, str) or not target.startswith("target_") or not target.replace("_", "").isalnum():
        raise ValueError("invalid target_id")
    previous = index.get("targets", {}).get(target, [])[-1] if index.get("targets", {}).get(target) else None
    snapshot = build_snapshot(report, previous)
    directory = root / target
    path = directory / f"{snapshot['snapshot_id']}.json"
    directory.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8") as handle:
            json.dump(snapshot, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError as exc:
        raise FileExistsError("immutable snapshot already exists") from exc
    try:
        index.setdefault("targets", {}).setdefault(target, []).append(snapshot["snapshot_id"])
        _atomic_json(index_path, index)
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return snapshot, path
