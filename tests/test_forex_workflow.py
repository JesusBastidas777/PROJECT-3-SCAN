import sys
from pathlib import Path
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scanner import FOREXSCANWorkflow, SCANConfig, SCANService


class FOREXWorkflowTests(unittest.TestCase):
    def test_empty_runtime_is_valid_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            response = FOREXSCANWorkflow(SCANService(SCANConfig(Path(directory)))).operational_summary()
        self.assertIsNone(response.data["latest_scan"])
        self.assertEqual(response.data["status"]["state"], "idle")
