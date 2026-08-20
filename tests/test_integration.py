import sys
from pathlib import Path
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from scanner.changes import compare_snapshots
from scanner.contract import build_report_v2, validate_report_shape
from scanner.events import events_from_report, validate_event
from scanner.snapshots import build_snapshot, save_snapshot

def report(state, timestamp):
    item = {"port": 8080, "transport": "tcp", "state": state, "state_evidence": {"method": "tcp_connect", "result": "connected" if state == "open" else "connection_refused"}}
    return build_report_v2(target_input="127.0.0.1/32", network="127.0.0.1/32", host_results={"127.0.0.1": [item]}, ports=[8080], started_at=timestamp, completed_at=timestamp, duration_ms=0, ping_timeout=.1, connect_timeout=.1, workers=1, max_hosts=1, banners_enabled=False, banner_limits={})

class PipelineIntegrationTests(unittest.TestCase):
    def test_report_snapshot_diff_event_pipeline(self):
        first = report("open", "2026-08-20T00:00:00.000Z"); second = report("closed", "2026-08-20T00:01:00.000Z")
        validate_report_shape(first)
        self.assertEqual(compare_snapshots(build_snapshot(first), build_snapshot(second))["changes"][0]["change_type"], "endpoint_state_changed")
        for event in events_from_report(second): validate_event(event)
        with tempfile.TemporaryDirectory() as directory:
            _, path = save_snapshot(first, Path(directory)); self.assertTrue(path.exists())
