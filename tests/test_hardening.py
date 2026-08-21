import copy
import json
import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from scanner.changes import build_comparison, validate_comparison
from scanner.contract import build_report_v2, validate_report_shape
from scanner.discovery_evidence import discovery_observation
from scanner.event_io import event_document, prepare_events, validate_batch
from scanner.events import events_from_report, validate_events_for_report
from scanner.observations import tcp_observation
from scanner.snapshots import build_snapshot, validate_snapshot
from scanner.feed import validate_feed
from scanner.comparability import validate_comparison_v2

def report(state="open", stamp="2026-01-01T00:00:00.000Z"):
    endpoint = tcp_observation(443, state, "connected" if state == "open" else "connection_refused")
    endpoint["tls"] = {"status":"collected","method":"tls_handshake","protocol":"TLSv1.3","certificate_sha256":"a"*64,"trusted":False,"validation_performed":False}
    return build_report_v2(target_input="127.0.0.1/32", network="127.0.0.1/32", host_results={"127.0.0.1":[endpoint]}, ports=[443], started_at=stamp, completed_at=stamp, duration_ms=0, ping_timeout=1, connect_timeout=1, workers=1, max_hosts=1, banners_enabled=False, banner_limits={}, discovery_observations=[discovery_observation("127.0.0.1","connected",method="tcp_connect",port=443)], name_observations=[{"address":"127.0.0.1","source":"ptr","status":"resolved","trusted":False,"timeout_guarantee":"best_effort","names":["localhost"]}], tls_configuration={"enabled":True}, dns_configuration={"enabled":True})

class HardeningTests(unittest.TestCase):
    def test_full_artifact_chain_and_references(self):
        before = report(); after = report("closed", "2026-01-02T00:00:00.000Z")
        validate_report_shape(before); left = build_snapshot(before); right = build_snapshot(after); validate_snapshot(left)
        comparison = build_comparison(left, right); validate_comparison(comparison)
        events = events_from_report(after); validate_events_for_report(events, after)
        batch = event_document(prepare_events(events, max_event_bytes=16384, privacy="hash-only"), "batch-json"); validate_batch(batch)
        ndjson = event_document(events, "ndjson"); self.assertEqual(len(ndjson.splitlines()), len(events))
    def test_report_cross_invariants_reject_corruption(self):
        value = report(); value["summary"]["observations"] = 99
        with self.assertRaises(ValueError): validate_report_shape(value)
        value = report(); value["observations"][0]["asset_id"] = "asset_missing"
        with self.assertRaises(ValueError): validate_report_shape(value)
    def test_capabilities_are_executed_not_requested(self):
        value = build_report_v2(target_input="127.0.0.1/32", network="127.0.0.1/32", host_results={}, ports=[], started_at="2026-01-01T00:00:00.000Z", completed_at="2026-01-01T00:00:00.000Z", duration_ms=0, ping_timeout=1, connect_timeout=1, workers=1, max_hosts=1, banners_enabled=True, banner_limits={}, tls_configuration={"enabled":True}, dns_configuration={"enabled":True})
        self.assertFalse(value["capabilities"]["passive_banners"]); self.assertFalse(value["capabilities"]["tls_handshake"]); self.assertFalse(value["capabilities"]["reverse_dns"])
    def test_contract_schemas_are_parseable_and_substantive(self):
        root = Path(__file__).resolve().parents[1]
        for path in (root / "schemas").glob("*.schema.json"):
            value = json.loads(path.read_text()); self.assertEqual(value["type"], "object"); self.assertGreaterEqual(len(value.get("required", [])), 2)
        fixtures = root / "tests" / "fixtures" / "contracts"
        validate_snapshot(json.loads((fixtures / "snapshot-1.0.json").read_text()))
        validate_comparison(json.loads((fixtures / "comparison-1.0.json").read_text()))
        validate_batch(json.loads((fixtures / "batch-1.0.json").read_text()))
        validate_feed(json.loads((fixtures / "feed-1.0.json").read_text()))
    def test_no_prohibited_conclusions(self):
        text = json.dumps({"report":report(),"comparison":build_comparison(build_snapshot(report()),build_snapshot(report()))}).lower()
        for phrase in ("vulnerable","compromised","firewall detected","cve applies","os confirmed","certificate proves identity","host offline"):
            self.assertNotIn(phrase, text)
