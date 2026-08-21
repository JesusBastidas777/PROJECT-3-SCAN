import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scanner.runtime_health import RuntimeHealth, heartbeat_is_stale
from scanner.runtime_paths import SCANRuntimeConfig, prepare_runtime


class RuntimeHealthTests(unittest.TestCase):
    def test_sequence_survives_monitor_restart_and_heartbeat_stales(self):
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            config = SCANRuntimeConfig(Path(directory) / "runtime", heartbeat_max_age_seconds=5)
            prepare_runtime(config)
            first = RuntimeHealth(config, "boot-a", now=lambda: now)
            _, heartbeat = first.publish(lifecycle="idle")
            second = RuntimeHealth(config, "boot-b", now=lambda: now)
            status, _ = second.publish(lifecycle="starting")
        self.assertGreater(status["sequence"], heartbeat["sequence"])
        self.assertTrue(heartbeat_is_stale(heartbeat, now=now + timedelta(seconds=6)))

    def test_atomic_documents_are_valid_json(self):
        with tempfile.TemporaryDirectory() as directory:
            config = SCANRuntimeConfig(Path(directory) / "runtime")
            prepare_runtime(config)
            RuntimeHealth(config, "boot").publish(lifecycle="idle")
            json.loads(config.status_path.read_text(encoding="utf-8"))
            json.loads(config.heartbeat_path.read_text(encoding="utf-8"))
