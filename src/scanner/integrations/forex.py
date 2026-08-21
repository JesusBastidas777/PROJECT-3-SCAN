"""FOREX workflows composed exclusively from the public SCAN service."""
from __future__ import annotations

from scanner.models import SCANResponseV1


class FOREXSCANWorkflow:
    def __init__(self, service):
        required = ("check", "status", "capabilities", "plan_scan", "get_latest_scan")
        if not all(hasattr(service, name) for name in required):
            raise TypeError("service must provide the public SCANService interface")
        self.service = service

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
        return self.service.plan_scan(request)
