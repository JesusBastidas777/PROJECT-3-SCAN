import json
import sys
from pathlib import Path
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scanner.publisher import publish_result
from scanner.runtime import SCANRuntime
from scanner.runtime_paths import SCANRuntimeConfig
from unittest.mock import patch
from scanner.configuration import ScanRequest, resolve_request
from scanner.scan_parser import create_parser
from scanner.scan_pipeline import execute_scan


def report22():
    args = create_parser().parse_args(["127.0.0.1/32", "--schema-version", "2.2", "--workers", "1"])
    with patch("scanner.scan_pipeline.discover_host_evidence", return_value=[]):
        return execute_scan(resolve_request(ScanRequest.from_namespace(args)))


class PublisherTests(unittest.TestCase):
    def test_ordered_publication_confirms_visible_sequence(self):
        with tempfile.TemporaryDirectory() as directory:
            config = SCANRuntimeConfig(Path(directory) / "runtime")
            runtime = SCANRuntime(config); runtime.start(); runtime.begin_job("pending", "target"); runtime.transition_job("running")
            report = report22(); runtime.active_job.scan_id = report["scan_id"]; runtime.transition_job("completed")
            result = publish_result(report, runtime)
            latest = json.loads(config.latest_scan_path.read_text(encoding="utf-8"))
        self.assertEqual(latest["scan_id"], report["scan_id"])
        self.assertEqual(result["heartbeat"]["sequence"], result["heartbeat"]["last_publish_sequence"])

    def test_auto_outbox_is_opt_in(self):
        with tempfile.TemporaryDirectory() as directory:
            config = SCANRuntimeConfig(Path(directory) / "runtime", auto_enqueue=False)
            runtime = SCANRuntime(config); runtime.start(); runtime.begin_job("pending", "target"); runtime.transition_job("running")
            report = report22(); runtime.active_job.scan_id = report["scan_id"]; runtime.transition_job("completed")
            publish_result(report, runtime)
            self.assertEqual(list((config.outbox_dir / "pending").iterdir()), [])
