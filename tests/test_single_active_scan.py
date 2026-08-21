import sys
from pathlib import Path
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scanner.errors import ScanAlreadyRunning
from scanner.runtime import SCANRuntime
from scanner.runtime_paths import SCANRuntimeConfig


class SingleActiveScanTests(unittest.TestCase):
    def test_second_active_job_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = SCANRuntime(SCANRuntimeConfig(Path(directory) / "runtime"))
            runtime.start(); runtime.begin_job("scan-a", "target-a")
            with self.assertRaises(ScanAlreadyRunning): runtime.begin_job("scan-b", "target-b")
