"""Validated local FOREX event serialization and atomic output."""
from __future__ import annotations
import os
from pathlib import Path
import tempfile
from collections.abc import Mapping, Sequence
from typing import Any
from scanner.contract import canonical_json
from scanner.events import validate_event
from scanner.report import serialize_report, write_report_atomic

SENSITIVE_KEYS = {"text", "data_base64", "names", "subject_fields", "issuer_fields"}
def redact_event(event: Mapping[str, Any], policy: str) -> dict[str, Any]:
    def clean(value: Any) -> Any:
        if isinstance(value, Mapping): return {key: clean(item) for key, item in value.items() if policy == "full" or key not in SENSITIVE_KEYS}
        if isinstance(value, list): return [clean(item) for item in value]
        return value
    return clean(dict(event))
def prepare_events(events: Sequence[Mapping[str, Any]], *, max_event_bytes: int, privacy: str) -> list[dict[str, Any]]:
    if max_event_bytes < 256: raise ValueError("max event bytes must be at least 256")
    output = []
    for event in events:
        value = redact_event(event, privacy); validate_event(value)
        if len(canonical_json(value).encode("utf-8")) > max_event_bytes: raise ValueError("FOREX event exceeds configured payload limit")
        output.append(value)
    return output
def event_document(events: Sequence[Mapping[str, Any]], format_name: str) -> dict[str, Any] | str:
    if format_name == "legacy-json": return {"event_schema_version": "1.0", "events": list(events)}
    if format_name == "batch-json": return {"batch_schema_version": "1.0", "document_type": "forex_event_batch", "event_schema_versions": sorted({str(item["event_schema_version"]) for item in events}), "count": len(events), "truncated": any(item.get("event_type") == "scan.partial" for item in events), "events": list(events)}
    if format_name == "ndjson": return "".join(canonical_json(item) + "\n" for item in events)
    raise ValueError("unsupported event format")
def _atomic_text(path: Path, text: str) -> None:
    destination = Path(path); destination.parent.mkdir(parents=True, exist_ok=True); temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\n", dir=destination.parent, prefix=f".{destination.name}.", suffix=".tmp", delete=False) as handle:
            temporary = Path(handle.name); handle.write(text); handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, destination); temporary = None
    finally:
        if temporary is not None: temporary.unlink(missing_ok=True)
def write_events(events: Sequence[Mapping[str, Any]], destination: str | Path, *, format_name: str, max_event_bytes: int, privacy: str) -> None:
    values = prepare_events(events, max_event_bytes=max_event_bytes, privacy=privacy); document = event_document(values, format_name)
    if str(destination) == "-":
        import sys
        sys.stdout.write(document if isinstance(document, str) else serialize_report(document)); return
    if isinstance(document, str): _atomic_text(Path(destination), document)
    else: write_report_atomic(document, Path(destination))
