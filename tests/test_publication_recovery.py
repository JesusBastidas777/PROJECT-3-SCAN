import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scanner.publisher import publish_result
from scanner.report import write_report_atomic
from scanner.runtime import SCANRuntime
from scanner.runtime_paths import SCANRuntimeConfig
from test_publisher import report22


class PublicationRecoveryTests(unittest.TestCase):
    def test_failed_latest_replacement_preserves_previous(self):
        with tempfile.TemporaryDirectory() as directory:
            config = SCANRuntimeConfig(Path(directory) / "runtime")
            runtime = SCANRuntime(config); runtime.start(); runtime.begin_job("pending", "target"); runtime.transition_job("running")
            write_report_atomic({"previous": True}, config.latest_scan_path)
            report = report22(); runtime.active_job.scan_id = report["scan_id"]; runtime.transition_job("completed")
            with patch("scanner.publisher.write_report_atomic", side_effect=OSError("disk full")):
                with self.assertRaises(OSError): publish_result(report, runtime)
            self.assertIn("previous", config.latest_scan_path.read_text(encoding="utf-8"))
