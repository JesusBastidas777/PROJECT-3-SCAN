import copy
import json
import unittest

from scanner.comparability import build_comparison_v2, validate_comparison_v2
from scanner.contract import build_report_v21, validate_report_shape
from scanner.discovery_evidence import discovery_observation
from scanner.feed import build_feed, validate_feed
from scanner.event_io import event_document, prepare_events, validate_batch
from scanner.events import events_from_report, validate_events_for_report
from scanner.query import query_report
from scanner.snapshots import build_snapshot, validate_snapshot


def report(state="open", timeout=1):
    endpoint={"port":80,"transport":"tcp","state":state,"state_evidence":{"method":"tcp_connect","result":"connected" if state=="open" else "connection_refused"},"http":{"status":"collected","method":"HEAD","request_target":"/","status_code":200,"http_version":"1.1","headers":{},"bytes_read":0,"truncated":False,"redirect_followed":False,"authenticated":False,"trusted":False}}
    neighbor={"neighbor_observation_id":"neighbor_"+"a"*24,"address":"192.168.1.2","ip_version":4,"interface":"eth0","neighbor_state":"cached","source":"system_neighbor_table","backend":"mock","network_context":"linux_host","active_probe":False,"trusted":False,"scope":"local_link","limitations":["cache_entry_does_not_prove_current_reachability"],"link_layer_sha256":"b"*64}
    return build_report_v21(target_input="192.168.1.2/32",network="192.168.1.2/32",host_results={"192.168.1.2":[endpoint]},ports=[80],started_at="2026-01-01T00:00:00.000Z",completed_at="2026-01-01T00:00:01.000Z",duration_ms=1000,ping_timeout=1,connect_timeout=timeout,workers=1,max_hosts=1,banners_enabled=False,banner_limits={},discovery_observations=[discovery_observation("192.168.1.2","unsupported",error_code="ping_unavailable")],discovery_configuration={"mode":"icmp-tcp","ports":[80],"connect_timeout_seconds":1,"max_endpoints":1},neighbor_observations=[neighbor],neighbor_execution={"supported":True,"backend":"mock","eligible":1,"attempted":1,"observed":1,"truncated":False,"limits":{"workers":0,"max_records":1}},neighbor_configuration={"enabled":True,"privacy":"hash-only","max_records":1},http_configuration={"enabled":True,"ports":[80],"workers":1,"max_endpoints":1},correlation_configuration={"enabled":True,"max_signals":10,"max_relations":10,"ruleset_version":"1.0"})


class FourthStageHardeningTests(unittest.TestCase):
    def test_full_report_snapshot_query_feed_comparison_chain(self):
        first=report(); second=report("closed")
        validate_report_shape(first); left=build_snapshot(first); right=build_snapshot(second); validate_snapshot(left)
        self.assertEqual(query_report(first,coverage=True)["query"],"coverage")
        feed=build_feed(first,snapshot=left); validate_feed(feed); self.assertEqual(feed["report_ref"],left["snapshot_id"])
        comparison=build_comparison_v2(left,right); validate_comparison_v2(comparison)
        events=events_from_report(first); validate_events_for_report(events,first)
        validate_batch(event_document(prepare_events(events,max_event_bytes=16384,privacy="hash-only"),"batch-json"))

    def test_cross_reference_fingerprint_and_privacy_corruption(self):
        value=report(); broken=copy.deepcopy(value); broken["coverage"]["phases"]["neighbors"]["evidence_refs"]=["missing"]
        with self.assertRaises(ValueError): validate_report_shape(broken)
        snapshot=build_snapshot(value); broken_snapshot=copy.deepcopy(snapshot); broken_snapshot["measurement_scope_fingerprint"]="0"*64
        with self.assertRaises(ValueError): validate_snapshot(broken_snapshot)
        feed=build_feed(value); broken_feed=copy.deepcopy(feed); broken_feed["omitted_counts"]["assets"]=1; broken_feed["truncated"]=False
        with self.assertRaises(ValueError): validate_feed(broken_feed)
        self.assertNotIn("link_layer_address",json.dumps(value))

    def test_semantic_boundaries_and_runtime_capabilities(self):
        value=report(); text=json.dumps({"report":value,"feed":build_feed(value)}).lower()
        for phrase in ("vulnerable","compromised","firewall detected","cve applies","os confirmed","certificate proves identity","ptr proves identity","host offline","risk_score"):
            self.assertNotIn(phrase,text)
        self.assertEqual(value["capabilities"],value["capability_execution"])
        self.assertEqual(value["coverage"]["phases"]["discovery"]["support"]["status"],"unsupported")
