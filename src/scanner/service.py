"""Narrow public SCAN facade for FOREX and other local consumers."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from scanner.changes import compare_snapshots
from scanner.configuration import ScanRequest, resolve_request
from scanner.errors import ContractInvalid, RequestInvalid, ScanNotFound
from scanner.findings import findings_from_report
from scanner.loaders import load_json_document, load_report_or_snapshot, load_snapshot
from scanner.models import SCANConfig, SCANResponseV1
from scanner.planner import build_scan_plan
from scanner.readiness import build_readiness


class SCANService:
    """Public facade; callers need not import scanner implementation modules."""

    def __init__(self, config: SCANConfig):
        if not isinstance(config, SCANConfig):
            raise TypeError("config must be SCANConfig")
        self.config = config

    def check(self) -> SCANResponseV1:
        if self.config.runtime is not None:
            readiness = build_readiness(self.config.runtime)
            return SCANResponseV1(
                status="success" if readiness["ready"] else "degraded",
                data={"ready": readiness["ready"], "readiness": readiness},
                metadata={"operation": "check"},
            )
        available = self.config.reports_dir.exists()
        return SCANResponseV1(
            status="success" if available else "degraded",
            data={"ready": available}, metadata={"operation": "check"},
        )

    def health(self) -> SCANResponseV1:
        return self.check()

    def status(self) -> SCANResponseV1:
        scans = self._scan_paths()
        return SCANResponseV1(data={"state": "idle", "scan_count": len(scans)})

    def capabilities(self) -> SCANResponseV1:
        return SCANResponseV1(data={"capabilities": [
            "icmp_discovery", "tcp_discovery", "tcp_connect", "passive_banners",
            "tls_handshake", "reverse_dns", "neighbor_cache", "http_metadata",
            "fingerprints", "inventory", "coverage", "checkpoint_resume",
        ]})

    def plan_scan(self, request: ScanRequest) -> SCANResponseV1:
        if not isinstance(request, ScanRequest):
            raise RequestInvalid("request must be ScanRequest")
        try:
            plan = build_scan_plan(resolve_request(request))
        except (TypeError, ValueError) as exc:
            raise RequestInvalid(str(exc)) from exc
        return SCANResponseV1(data={"plan": plan})

    def _scan_paths(self) -> list[Path]:
        root = self.config.reports_dir
        if not root.exists():
            return []
        return sorted(
            (path for path in root.glob("*.json") if not path.is_symlink()),
            key=lambda path: path.name,
        )

    def _load_scan(self, path: Path) -> dict[str, Any]:
        try:
            report, _ = load_report_or_snapshot(path)
            return report
        except (OSError, ValueError) as exc:
            raise ContractInvalid(str(exc), {"path": str(path)}) from exc

    def get_scan(self, scan_id: str) -> SCANResponseV1:
        for path in self._scan_paths():
            report = self._load_scan(path)
            if report.get("scan_id") == scan_id:
                return SCANResponseV1(data={"scan": report})
        raise ScanNotFound("scan was not found", {"scan_id": scan_id})

    def get_latest_scan(self) -> SCANResponseV1:
        reports = [self._load_scan(path) for path in self._scan_paths()]
        if not reports:
            raise ScanNotFound("no scans are available")
        report = max(reports, key=lambda item: str(item.get("completed_at", item.get("timestamp", ""))))
        return SCANResponseV1(data={"scan": report})

    def list_scans(self, limit: int = 100) -> SCANResponseV1:
        if limit < 1 or limit > 1000:
            raise RequestInvalid("limit must be between 1 and 1000")
        reports = [self._load_scan(path) for path in self._scan_paths()]
        reports.sort(key=lambda item: str(item.get("completed_at", item.get("timestamp", ""))), reverse=True)
        items = [{key: report.get(key) for key in ("scan_id", "completed_at", "duration_ms", "partial")} for report in reports[:limit]]
        return SCANResponseV1(data={"scans": items}, metadata={"count": len(items)})

    def get_findings(self, scan_id: str) -> SCANResponseV1:
        report = self.get_scan(scan_id).data["scan"]
        findings = findings_from_report(report)
        return SCANResponseV1(data={"findings": findings}, metadata={"count": len(findings)})

    def get_coverage(self, scan_id: str) -> SCANResponseV1:
        report = self.get_scan(scan_id).data["scan"]
        return SCANResponseV1(data={"coverage": report.get("coverage", {})})

    def get_changes(self, scan_id: str, baseline_id: str | None = None) -> SCANResponseV1:
        if self.config.history_dir is None:
            raise ScanNotFound("snapshot history is unavailable")
        snapshots = []
        for path in sorted(self.config.history_dir.glob("*/*.json")):
            if path.name == "index.json" or path.is_symlink():
                continue
            try:
                snapshots.append(load_snapshot(path))
            except (OSError, ValueError):
                continue
        current = next((item for item in snapshots if item["report"].get("scan_id") == scan_id), None)
        baseline = next((item for item in snapshots if item.get("snapshot_id") == baseline_id), None) if baseline_id else None
        if current is None:
            raise ScanNotFound("current scan snapshot was not found", {"scan_id": scan_id})
        if baseline is None:
            candidates = [item for item in snapshots if item is not current and item["report"]["target"]["target_id"] == current["report"]["target"]["target_id"]]
            baseline = candidates[-1] if candidates else None
        if baseline is None:
            raise ScanNotFound("baseline snapshot was not found")
        return SCANResponseV1(data={"comparison": compare_snapshots(baseline, current)})

    def outbox_status(self) -> SCANResponseV1:
        root = self.config.outbox_dir
        counts = {state: 0 for state in ("pending", "processing", "acknowledged", "failed")}
        if root is not None and root.exists() and not root.is_symlink():
            for state in counts:
                counts[state] = sum(1 for path in (root / state).glob("outbox_*.json") if not path.is_symlink())
        return SCANResponseV1(data={"outbox": counts})
