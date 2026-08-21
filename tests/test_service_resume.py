import sys
from pathlib import Path
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scanner import SCANConfig, SCANService
from scanner.errors import CheckpointIncompatible
from scanner.runtime_paths import SCANRuntimeConfig, prepare_runtime


class ServiceResumeTests(unittest.TestCase):
    def test_missing_checkpoint_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            config = SCANRuntimeConfig(Path(directory) / "runtime"); prepare_runtime(config)
            service = SCANService(SCANConfig(config.reports_dir, runtime=config))
            with self.assertRaises(CheckpointIncompatible): service.resume_scan("checkpoint_missing")
