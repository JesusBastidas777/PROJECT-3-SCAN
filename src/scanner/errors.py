"""Stable public SCAN error taxonomy."""
from __future__ import annotations

from typing import Any, Mapping


class SCANError(Exception):
    code = "scan_error"

    def __init__(self, message: str, details: Mapping[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.details = dict(details or {})

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.details:
            value["details"] = self.details
        return value


def _error(name: str, code: str) -> type[SCANError]:
    return type(name, (SCANError,), {"code": code})


RequestInvalid = _error("RequestInvalid", "request_invalid")
TargetPolicyRejected = _error("TargetPolicyRejected", "target_policy_rejected")
ConfigurationInvalid = _error("ConfigurationInvalid", "configuration_invalid")
RuntimeUnavailable = _error("RuntimeUnavailable", "runtime_unavailable")
ScanAlreadyRunning = _error("ScanAlreadyRunning", "scan_already_running")
ScanNotFound = _error("ScanNotFound", "scan_not_found")
CheckpointIncompatible = _error("CheckpointIncompatible", "checkpoint_incompatible")
ContractInvalid = _error("ContractInvalid", "contract_invalid")
BudgetExhausted = _error("BudgetExhausted", "budget_exhausted")
ScanInterrupted = _error("ScanInterrupted", "interrupted_cancelled")
PublicationError = _error("PublicationError", "publication_error")
OutboxError = _error("OutboxError", "outbox_error")
