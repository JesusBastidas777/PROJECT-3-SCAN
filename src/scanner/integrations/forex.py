"""FOREX workflows composed exclusively from the public SCAN service."""
from __future__ import annotations

from scanner.models import SCANResponseV1


class FOREXSCANWorkflow:
    def __init__(self, service):
        required = ("check", "status", "capabilities", "plan_scan", "get_latest_scan")
        if not all(hasattr(service, name) for name in required):
            raise TypeError("service must provide the public SCANService interface")
        self.service = service
        self._planned_request = None
        self._baseline_id = None

    def operational_summary(self) -> SCANResponseV1:
        status = self.service.status().to_dict()["data"]
        capabilities = self.service.capabilities().to_dict()["data"]["capabilities"]
        try:
            latest = self.service.get_latest_scan().to_dict()["data"]["scan"]
        except Exception as exc:
            if getattr(exc, "code", None) != "scan_not_found":
                raise
            latest = None
        return SCANResponseV1(data={
            "status": status, "capabilities": capabilities, "latest_scan": latest,
        })

    def plan(self, request) -> SCANResponseV1:
        response = self.service.plan_scan(request)
        self._planned_request = request
        return response

    def start(self, request) -> SCANResponseV1:
        if request is not self._planned_request and request != self._planned_request:
            raise ValueError("START requires the exact request shown by PLAN")
        return self.service.start_scan(request)

    def cancel(self, scan_id: str) -> SCANResponseV1:
        return self.service.cancel_scan(scan_id)

    def resume(self, checkpoint_id: str) -> SCANResponseV1:
        return self.service.resume_scan(checkpoint_id)

    def select_baseline(self, snapshot_id: str) -> SCANResponseV1:
        if not isinstance(snapshot_id, str) or not snapshot_id.startswith("snapshot_"):
            raise ValueError("invalid baseline identifier")
        self._baseline_id = snapshot_id
        return SCANResponseV1(data={"baseline_id": snapshot_id})

    def export(self, scan_id, destination, *, overwrite=False) -> SCANResponseV1:
        return self.service.export_scan(scan_id, destination, overwrite=overwrite)

    def retry_failed_publication(self, scan_id: str) -> SCANResponseV1:
        return self.service.retry_publication(scan_id)

    def view(self, name: str, *, limit: int = 20) -> SCANResponseV1:
        if name == "runtime":
            return SCANResponseV1(data={
                "readiness": self.service.check().data,
                "heartbeat": self.service.health().data,
                "status": self.service.status().data,
                "capabilities": self.service.capabilities().data,
                "outbox": self.service.outbox_status().data,
            })
        if name == "history":
            return self.service.list_scans(limit=limit)
        latest = self.service.get_latest_scan().data["scan"]
        scan_id = latest.get("scan_id")
        if name == "overview":
            return SCANResponseV1(data={"overview": latest})
        report = self.service.get_scan(scan_id).data["scan"]
        if name == "assets":
            return SCANResponseV1(data={"assets": report.get("assets", [])[:limit]})
        if name == "endpoints":
            return SCANResponseV1(data={"endpoints": report.get("observations", [])[:limit]})
        if name == "findings":
            response = self.service.get_findings(scan_id)
            return SCANResponseV1(data={"findings": response.data["findings"][:limit]})
        if name == "coverage":
            return self.service.get_coverage(scan_id)
        if name == "changes":
            return self.service.get_changes(scan_id, self._baseline_id)
        raise ValueError("unknown FOREX SCAN view")
