import json, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from scanner.publisher import publish_result
from scanner.runtime import SCANRuntime
from scanner.runtime_paths import SCANRuntimeConfig
from test_publisher import report22


class FOREXRuntimeE2E(unittest.TestCase):
    def test_public_chain_without_private_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            config = SCANRuntimeConfig(Path(directory) / "runtime")
            runtime = SCANRuntime(config); runtime.start(); runtime.begin_job("pending", "target"); runtime.transition_job("running")
            report = report22(); runtime.active_job.scan_id = report["scan_id"]; runtime.transition_job("completed")
            result = publish_result(report, runtime)
            latest = json.loads(config.latest_scan_path.read_text()); heartbeat = json.loads(config.heartbeat_path.read_text())
        self.assertEqual(latest["scan_id"], report["scan_id"])
        self.assertEqual(heartbeat["last_publish_sequence"], result["status"]["sequence"])
