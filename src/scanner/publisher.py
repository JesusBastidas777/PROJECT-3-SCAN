"""Durable ordered publication of SCAN results for FOREX."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Any, Mapping

from scanner.contract import semantic_hash, validate_report_shape
from scanner.feed import build_feed
from scanner.operational_view import build_operational_view, validate_operational_view
from scanner.outbox import enqueue
from scanner.report import serialize_report, write_report_atomic
from scanner.runtime_paths import SCANRuntimeConfig


def _atomic_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name); stream.write(text); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path); temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _append_bounded_history(config: SCANRuntimeConfig, view: Mapping[str, Any]) -> None:
    existing: list[bytes] = []
    if config.public_history_path.exists():
        existing = [line for line in config.public_history_path.read_bytes().splitlines() if line]
    encoded = serialize_report(dict(view)).encode("utf-8")
    lines = (existing + [encoded])[-config.history_max_entries:]
    while lines and sum(len(line) + 1 for line in lines) > config.history_max_bytes:
        lines.pop(0)
    if not lines:
        raise ValueError("operational history entry exceeds configured limit")
    _atomic_text(config.public_history_path, b"\n".join(lines).decode("utf-8") + "\n")


def outbox_counts(config: SCANRuntimeConfig) -> dict[str, int]:
    return {state: len(list((config.outbox_dir / state).glob("outbox_*.json"))) for state in ("pending", "processing", "acknowledged", "failed")}


def publish_result(report: dict[str, Any], runtime, *, comparison: Mapping[str, Any] | None = None) -> dict[str, Any]:
    config = runtime.config
    validate_report_shape(report)
    if report.get("schema_version") != "2.2":
        raise ValueError("FOREX publication requires Report 2.2")
    if report.get("partial") or report.get("acquisition", {}).get("resumed_from"):
        report["baseline_eligible"] = False
    report_path = config.reports_dir / f"{report['scan_id']}.json"
    write_report_atomic(report, report_path)
    references = {"report": f"private/reports/{report_path.name}", "snapshot": None, "feed": None}
    feed = build_feed(report, privacy="hash-only")
    feed_path = config.private_dir / "feeds" / f"{report['scan_id']}.json"
    write_report_atomic(feed, feed_path); references["feed"] = f"private/feeds/{feed_path.name}"
    manifest = {
        "publication_manifest_schema_version": "1.0", "document_type": "scan_publication_manifest",
        "scan_id": report["scan_id"], "report_hash": semantic_hash(report), "references": references,
    }
    manifest_path = config.private_dir / "manifests" / f"{report['scan_id']}.json"
    write_report_atomic(manifest, manifest_path)
    view = build_operational_view(report, runtime_status={"lifecycle": runtime.lifecycle, "job_state": runtime.active_job.state}, references=references, outbox_state=outbox_counts(config), comparison=comparison)
    payload = serialize_report(view).encode("utf-8")
    if len(payload) > config.public_max_bytes:
        raise ValueError("operational view exceeds public size limit")
    write_report_atomic(view, config.latest_scan_path)
    _append_bounded_history(config, view)
    if config.auto_enqueue:
        enqueue(config.outbox_dir, feed, privacy="hash-only")
        view["outbox_state"] = outbox_counts(config)
        write_report_atomic(view, config.latest_scan_path)
    status, heartbeat = runtime.health.publish(
        lifecycle=runtime.lifecycle, job=runtime.active_job,
        last_successful_scan_id=runtime.last_successful_scan_id, confirm_publication=True,
    )
    return {"view": view, "manifest": manifest, "status": status, "heartbeat": heartbeat}
