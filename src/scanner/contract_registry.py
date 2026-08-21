"""Version-aware registry for all local SCAN and FOREX contracts."""
from __future__ import annotations
from collections.abc import Callable,Mapping
from dataclasses import dataclass
from scanner.changes import validate_comparison
from scanner.comparability import validate_comparison_v2
from scanner.contract import validate_report_shape
from scanner.event_io import validate_batch
from scanner.events import validate_event
from scanner.feed import validate_feed
from scanner.plan_contract import validate_plan
from scanner.snapshots import validate_snapshot
from scanner.checkpoints import validate_checkpoint
from scanner.operational_view import validate_operational_view
from scanner.readiness import validate_readiness
from scanner.runtime_health import validate_heartbeat, validate_runtime_status
@dataclass(frozen=True)
class ContractSpec:
    type_name: str; version: str; validator: Callable[[Mapping],None]
REGISTRY={("report",v):ContractSpec("report",v,validate_report_shape) for v in ("1.0","2.0","2.1","2.2")}
REGISTRY.update({("plan","1.0"):ContractSpec("plan","1.0",validate_plan),("snapshot","1.0"):ContractSpec("snapshot","1.0",validate_snapshot),("snapshot","1.1"):ContractSpec("snapshot","1.1",validate_snapshot),("comparison","1.0"):ContractSpec("comparison","1.0",validate_comparison),("comparison","2.0"):ContractSpec("comparison","2.0",validate_comparison_v2),("event","1.0"):ContractSpec("event","1.0",validate_event),("event_batch","1.0"):ContractSpec("event_batch","1.0",validate_batch),("feed","1.0"):ContractSpec("feed","1.0",validate_feed)})
REGISTRY[("checkpoint","1.0")]=ContractSpec("checkpoint","1.0",validate_checkpoint)
REGISTRY[("snapshot","1.2")]=ContractSpec("snapshot","1.2",validate_snapshot)
REGISTRY[("feed","1.1")]=ContractSpec("feed","1.1",validate_feed)
def _validate_receipt(value: Mapping) -> None:
    if value.get("migration_receipt_version")!="1.0" or value.get("document_type")!="scan_migration_receipt" or not all(key in value for key in ("source","destination","migration_rule","lossy","limitations")): raise ValueError("invalid migration receipt")
def _validate_outbox(value: Mapping) -> None:
    from scanner.contract import semantic_hash
    if value.get("outbox_schema_version")!="1.0" or value.get("document_type")!="forex_outbox_item" or semantic_hash(value.get("payload"))!=value.get("content_hash"): raise ValueError("invalid outbox item")
REGISTRY[("migration_receipt","1.0")]=ContractSpec("migration_receipt","1.0",_validate_receipt)
REGISTRY[("outbox","1.0")]=ContractSpec("outbox","1.0",_validate_outbox)
REGISTRY[("operational_view","1.0")]=ContractSpec("operational_view","1.0",validate_operational_view)
REGISTRY[("readiness","1.0")]=ContractSpec("readiness","1.0",validate_readiness)
REGISTRY[("heartbeat","1.0")]=ContractSpec("heartbeat","1.0",validate_heartbeat)
REGISTRY[("runtime_status","1.0")]=ContractSpec("runtime_status","1.0",validate_runtime_status)
def detect_contract(value: Mapping) -> tuple[str,str]:
    if "plan_schema_version" in value: return "plan",str(value["plan_schema_version"])
    if "schema_version" in value and (value.get("document_type")=="scan_report" or "scanner" in value): return "report",str(value["schema_version"])
    if "snapshot_id" in value and "report" in value: return "snapshot",str(value.get("snapshot_schema_version","1.0"))
    if "comparison_schema_version" in value: return "comparison",str(value["comparison_schema_version"])
    if value.get("document_type")=="forex_event_batch": return "event_batch",str(value.get("batch_schema_version"))
    if "event_id" in value: return "event",str(value.get("event_schema_version"))
    if "feed_schema_version" in value: return "feed",str(value["feed_schema_version"])
    if "checkpoint_schema_version" in value: return "checkpoint",str(value["checkpoint_schema_version"])
    if "migration_receipt_version" in value: return "migration_receipt",str(value["migration_receipt_version"])
    if "outbox_schema_version" in value: return "outbox",str(value["outbox_schema_version"])
    if "operational_view_schema_version" in value: return "operational_view",str(value["operational_view_schema_version"])
    if "readiness_schema_version" in value: return "readiness",str(value["readiness_schema_version"])
    if "heartbeat_schema_version" in value: return "heartbeat",str(value["heartbeat_schema_version"])
    if "status_schema_version" in value: return "runtime_status",str(value["status_schema_version"])
    raise ValueError("unknown_document_type")
def get_contract(type_name: str,version: str) -> ContractSpec:
    try: return REGISTRY[(type_name,version)]
    except KeyError as exc: raise ValueError("unsupported_version") from exc
