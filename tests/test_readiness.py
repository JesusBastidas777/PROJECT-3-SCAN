import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scanner.readiness import build_readiness, publish_readiness, validate_readiness
from scanner.runtime_paths import SCANRuntimeConfig


class ReadinessTests(unittest.TestCase):
    def test_ready_runtime_is_published_without_probes(self):
        with tempfile.TemporaryDirectory() as directory:
            config = SCANRuntimeConfig(Path(directory) / "runtime")
            with patch("scanner.scan_pipeline.discover_host_evidence") as probe:
                report = publish_readiness(config)
                probe.assert_not_called()
            self.assertTrue(report["ready"])
            validate_readiness(report)
            self.assertTrue(config.readiness_path.exists())

    def test_invalid_limit_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            report = build_readiness(SCANRuntimeConfig(Path(directory) / "runtime", history_max_entries=0))
        self.assertFalse(report["ready"])
        self.assertEqual(report["checks"]["configuration"], "critical")
