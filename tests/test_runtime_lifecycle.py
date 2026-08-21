import json
import sys
from pathlib import Path
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scanner.runtime import SCANRuntime
from scanner.runtime_paths import SCANRuntimeConfig


class RuntimeLifecycleTests(unittest.TestCase):
    def test_clean_lifecycle_and_partial_job(self):
        with tempfile.TemporaryDirectory() as directory:
            config = SCANRuntimeConfig(Path(directory) / "runtime")
            runtime = SCANRuntime(config, runtime_instance_id="boot-a")
            runtime.start()
            job = runtime.begin_job("scan-a", "127.0.0.1/32")
            job.transition("running")
            runtime.transition_job("cancelling")
            runtime.transition_job("partial")
            runtime.stop()
            status = json.loads(config.status_path.read_text(encoding="utf-8"))
        self.assertEqual(status["lifecycle"], "stopped")
        self.assertTrue(status["partial"])

    def test_invalid_transition_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = SCANRuntime(SCANRuntimeConfig(Path(directory) / "runtime"))
            runtime.start(); runtime.begin_job("scan-a", "target")
            with self.assertRaises(ValueError): runtime.transition_job("completed")
