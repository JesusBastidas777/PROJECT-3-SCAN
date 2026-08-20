"""Explicit deterministic snapshot retention planning and application."""
from __future__ import annotations
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
from typing import Any
from scanner.locking import FileLock
from scanner.report import write_report_atomic

def _timestamp(snapshot: dict[str, Any]) -> datetime:
    return datetime.fromisoformat(snapshot["report"]["completed_at"].replace("Z", "+00:00")).astimezone(timezone.utc)

def retain_snapshots(root: Path, *, keep_last: int | None = None, max_age_days: int | None = None, dry_run: bool = True, lock_timeout: float = 5.0, now: datetime | None = None) -> dict[str, Any]:
    if keep_last is None and max_age_days is None: raise ValueError("retention requires keep_last or max_age_days")
    if (keep_last is not None and keep_last < 1) or (max_age_days is not None and max_age_days < 1): raise ValueError("retention limits must be positive")
    supplied = Path(root)
    if supplied.is_symlink(): raise OSError("history root cannot be a symlink")
    resolved = supplied.resolve(); index_path = resolved / "index.json"
    with FileLock(resolved / ".scan-history.lock", timeout=lock_timeout):
        index = json.loads(index_path.read_text(encoding="utf-8")); current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        removed: list[str] = []; retained: dict[str, list[str]] = {}
        for target, identifiers in sorted(index.get("targets", {}).items()):
            records = []
            for identifier in identifiers:
                path = resolved / target / f"{identifier}.json"
                if not path.resolve().is_relative_to(resolved): raise OSError("snapshot path escapes history root")
                records.append((_timestamp(json.loads(path.read_text(encoding="utf-8"))), identifier, path))
            records.sort(key=lambda item: (item[0], item[1]))
            keep = {identifier for _, identifier, _ in (records[-keep_last:] if keep_last else records)}
            if max_age_days is not None:
                cutoff = current - timedelta(days=max_age_days); keep &= {identifier for timestamp, identifier, _ in records if timestamp >= cutoff}
            retained[target] = [identifier for _, identifier, _ in records if identifier in keep]
            removed.extend(identifier for _, identifier, _ in records if identifier not in keep)
            if not dry_run:
                for _, identifier, path in records:
                    if identifier not in keep: path.unlink()
        if not dry_run:
            index["targets"] = retained; index["retention_last_applied"] = {"removed": len(removed), "policy": {"keep_last": keep_last, "max_age_days": max_age_days}}
            write_report_atomic(index, index_path)
        return {"retention_schema_version": "1.0", "dry_run": dry_run, "policy": {"keep_last": keep_last, "max_age_days": max_age_days}, "removed_snapshot_ids": sorted(removed), "retained": retained}
