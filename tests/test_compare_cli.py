import io
import json
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import main
from scanner.contract import build_report_v2
from scanner.snapshots import build_snapshot

def snapshot(state, address="127.0.0.1"):
    item = {"port": 80, "transport": "tcp", "state": state, "state_evidence": {"method": "tcp_connect", "result": "connected" if state == "open" else "connection_refused"}}
    report = build_report_v2(target_input=f"{address}/32" if ":" not in address else f"{address}/128", network=f"{address}/32" if ":" not in address else f"{address}/128", host_results={address: [item]}, ports=[80], started_at="2026-01-01T00:00:00.000Z", completed_at="2026-01-01T00:00:00.000Z", duration_ms=0, ping_timeout=1, connect_timeout=1, workers=1, max_hosts=1, banners_enabled=False, banner_limits={})
    return build_snapshot(report)

class CompareCliTests(unittest.TestCase):
    def test_stdout_is_clean_deterministic_and_no_probes(self):
        with tempfile.TemporaryDirectory() as directory:
            baseline = Path(directory) / "a.json"; current = Path(directory) / "b.json"
            baseline.write_text(json.dumps(snapshot("open"))); current.write_text(json.dumps(snapshot("closed")))
            with patch("sys.stdout", new_callable=io.StringIO) as stdout, patch("main.collect_report") as scan:
                self.assertEqual(main.main(["compare", str(baseline), str(current), "--output", "-"]), 0)
            value = json.loads(stdout.getvalue()); self.assertEqual(value["comparison_schema_version"], "2.0"); self.assertEqual(value["policy"], "strict"); scan.assert_not_called()
    def test_corrupt_and_different_target_fail(self):
        with tempfile.TemporaryDirectory() as directory, patch("sys.stderr", new_callable=io.StringIO):
            a = Path(directory) / "a"; b = Path(directory) / "b"; a.write_text("bad"); b.write_text(json.dumps(snapshot("open")))
            self.assertEqual(main.main(["compare", str(a), str(b)]), 1)
            a.write_text(json.dumps(snapshot("open", "::1")))
            self.assertEqual(main.main(["compare", str(a), str(b)]), 1)
    def test_output_file_and_scan_alias(self):
        with tempfile.TemporaryDirectory() as directory:
            a = Path(directory) / "a"; b = Path(directory) / "b"; output = Path(directory) / "out.json"
            a.write_text(json.dumps(snapshot("open"))); b.write_text(json.dumps(snapshot("closed")))
            self.assertEqual(main.main(["compare", str(a), str(b), "--output", str(output)]), 0)
            self.assertEqual(json.loads(output.read_text())["document_type"], "snapshot_comparison")
        with patch("main.collect_report", return_value={"schema_version": "1.0"}), patch("main.write_report_atomic"), patch("sys.stderr", new_callable=io.StringIO):
            self.assertEqual(main.main(["scan", "127.0.0.1"]), 0)
