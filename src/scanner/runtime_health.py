"""Atomic heartbeat and status contracts for the SCAN runtime."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from typing import Any, Callable

from scanner.report import write_report_atomic
from scanner.runtime_paths import SCANRuntimeConfig


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def validate_heartbeat(value: dict[str, Any]) -> None:
    required = {"heartbeat_schema_version", "document_type", "runtime_instance_id", "sequence", "timestamp", "lifecycle", "job_state", "scan_id", "target", "last_successful_scan_id", "last_publish_sequence", "partial", "errors", "freshness"}
    if required - value.keys() or value.get("heartbeat_schema_version") != "1.0" or value.get("document_type") != "scan_heartbeat":
        raise ValueError("invalid SCAN heartbeat contract")
    if value["lifecycle"] not in {"starting", "idle", "stopped", "crashed"}:
        raise ValueError("invalid runtime lifecycle")


def validate_runtime_status(value: dict[str, Any]) -> None:
    required = {"status_schema_version", "document_type", "runtime_instance_id", "sequence", "timestamp", "lifecycle", "job_state", "scan_id", "target", "last_successful_scan_id", "last_publish_sequence", "partial", "errors"}
    if required - value.keys() or value.get("status_schema_version") != "1.0" or value.get("document_type") != "scan_runtime_status":
        raise ValueError("invalid SCAN runtime status contract")


class RuntimeHealth:
    def __init__(self, config: SCANRuntimeConfig, runtime_instance_id: str, *, now: Callable[[], datetime] | None = None):
        self.config = config
        self.runtime_instance_id = runtime_instance_id
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.sequence = self._previous_sequence()
        self.last_publish_sequence: int | None = None

    def _previous_sequence(self) -> int:
        try:
            value = json.loads(self.config.status_path.read_text(encoding="utf-8"))
            return max(0, int(value.get("sequence", 0)))
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return 0

    def publish(self, *, lifecycle: str, job=None, last_successful_scan_id: str | None = None, confirm_publication: bool = False) -> tuple[dict[str, Any], dict[str, Any]]:
        self.sequence += 1
        if confirm_publication:
            self.last_publish_sequence = self.sequence
        timestamp = self.now()
        common = {
            "runtime_instance_id": self.runtime_instance_id, "sequence": self.sequence,
            "timestamp": _utc(timestamp), "lifecycle": lifecycle,
            "job_state": getattr(job, "state", None), "scan_id": getattr(job, "scan_id", None),
            "target": getattr(job, "target", None), "last_successful_scan_id": last_successful_scan_id,
            "last_publish_sequence": self.last_publish_sequence,
            "partial": bool(getattr(job, "partial", False)), "errors": list(getattr(job, "errors", [])),
        }
        status = {"status_schema_version": "1.0", "document_type": "scan_runtime_status", **common}
        heartbeat = {"heartbeat_schema_version": "1.0", "document_type": "scan_heartbeat", **common,
                     "freshness": {"expires_at": _utc(timestamp + timedelta(seconds=self.config.heartbeat_max_age_seconds))}}
        validate_runtime_status(status); validate_heartbeat(heartbeat)
        write_report_atomic(status, self.config.status_path)
        write_report_atomic(heartbeat, self.config.heartbeat_path)
        return status, heartbeat


def heartbeat_is_stale(value: dict[str, Any], *, now: datetime | None = None) -> bool:
    validate_heartbeat(value)
    current = now or datetime.now(timezone.utc)
    try:
        expires = datetime.fromisoformat(value["freshness"]["expires_at"].replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("invalid heartbeat freshness") from exc
    return current > expires
