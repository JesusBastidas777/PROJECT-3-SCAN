import json, sys, tempfile, unittest
from datetime import timedelta
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from scanner.errors import ScanAlreadyRunning
from scanner.runtime import SCANRuntime
from scanner.runtime_health import heartbeat_is_stale
from scanner.runtime_paths import SCANRuntimeConfig


class RuntimeRecoveryTests(unittest.TestCase):
    def test_restart_stale_and_cross_instance_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            config = SCANRuntimeConfig(Path(directory) / "runtime", heartbeat_max_age_seconds=1)
            first = SCANRuntime(config); first.start(); heartbeat = json.loads(config.heartbeat_path.read_text()); first.begin_job("one", "target")
            second = SCANRuntime(config); second.start()
            with self.assertRaises(ScanAlreadyRunning): second.begin_job("two", "target")
            first.transition_job("failed")
        expires = __import__("datetime").datetime.fromisoformat(heartbeat["freshness"]["expires_at"])
        self.assertTrue(heartbeat_is_stale(heartbeat, now=expires + timedelta(seconds=1)))
