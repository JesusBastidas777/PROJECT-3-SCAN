"""Stable baseline identities separated by measurement and presentation scope."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from scanner.contract import semantic_hash

PRESENTATION_KEYS = frozenset({"output", "events_output", "events_format", "feed", "query"})


def _without_presentation(configuration: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in configuration.items() if key not in PRESENTATION_KEYS}


def baseline_identity(report: Mapping[str, Any], *, presentation: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Return independent deterministic fingerprints for comparison policy."""
    configuration = dict(report.get("effective_configuration") or report.get("configuration") or {})
    measurement = {
        "target_id": report.get("target", {}).get("target_id"),
        "canonical_target": report.get("target", {}).get("network"),
        "report_schema": report.get("schema_version"),
        "ip_version": report.get("target", {}).get("ip_version"),
        "configuration": _without_presentation(configuration),
        "correlation_ruleset_version": configuration.get("correlation", {}).get("ruleset_version"),
    }
    return {
        "configuration_fingerprint": semantic_hash(configuration),
        "measurement_scope_fingerprint": semantic_hash(measurement),
        "presentation_fingerprint": semantic_hash(dict(presentation or {})),
        "measurement_scope": measurement,
    }
