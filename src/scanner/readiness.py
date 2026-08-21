"""Fail-closed runtime readiness without acquisition."""
from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Any

from scanner.contract import SUPPORTED_REPORT_VERSIONS
from scanner.report import write_report_atomic
from scanner.runtime_paths import SCANRuntimeConfig, prepare_runtime, validate_runtime_root


READINESS_SCHEMA_VERSION = "1.0"


def build_readiness(config: SCANRuntimeConfig) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    checks: dict[str, Any] = {
        "configuration": "healthy", "runtime_writable": False,
        "runtime_private": "not_checked", "schema_versions": list(SUPPORTED_REPORT_VERSIONS),
        "required_directories": False,
    }
    for name in ("heartbeat_max_age_seconds", "history_max_entries", "history_max_bytes", "public_max_bytes"):
        if getattr(config, name) <= 0:
            errors.append({"code": "invalid_limit", "message": f"{name} must be positive"})
    if "2.2" not in SUPPORTED_REPORT_VERSIONS:
        errors.append({"code": "unsupported_version", "message": "Report 2.2 is required for FOREX"})
    try:
        validate_runtime_root(config.root)
        prepare_runtime(config)
        marker = config.private_dir / ".readiness-write-test"
        marker.write_bytes(b"ready")
        marker.unlink()
        checks["runtime_writable"] = True
        checks["required_directories"] = all(path.is_dir() for path in config.required_directories())
        if os.name == "nt":
            checks["runtime_private"] = "windows_acl_operator_responsibility"
        else:
            mode = config.root.stat().st_mode & 0o777
            checks["runtime_private"] = oct(mode)
            if mode & 0o077:
                errors.append({"code": "privacy_permissions", "message": "runtime root permits group/world access"})
    except (OSError, ValueError) as exc:
        errors.append({"code": "runtime_invalid", "message": f"{type(exc).__name__}: {exc}"})
    if errors:
        checks["configuration"] = "critical"
    return {
        "readiness_schema_version": READINESS_SCHEMA_VERSION,
        "document_type": "scan_readiness", "timestamp": datetime.now(timezone.utc).isoformat(),
        "ready": not errors, "checks": checks, "errors": errors,
    }


def validate_readiness(value: dict[str, Any]) -> None:
    required = {"readiness_schema_version", "document_type", "timestamp", "ready", "checks", "errors"}
    if required - value.keys() or value.get("readiness_schema_version") != "1.0" or value.get("document_type") != "scan_readiness":
        raise ValueError("invalid SCAN readiness contract")
    if bool(value["errors"]) == bool(value["ready"]):
        raise ValueError("readiness status contradicts errors")


def publish_readiness(config: SCANRuntimeConfig, value: dict[str, Any] | None = None) -> dict[str, Any]:
    report = value or build_readiness(config)
    validate_readiness(report)
    write_report_atomic(report, config.readiness_path)
    return report
