import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import scanner
from scanner.errors import SCANError, ScanNotFound


class PublicAPIContractTests(unittest.TestCase):
    def test_narrow_exports(self):
        self.assertEqual(set(scanner.__all__), {"FOREXSCANWorkflow", "SCANConfig", "SCANError", "SCANResponseV1", "SCANService"})

    def test_stable_error(self):
        error = ScanNotFound("missing", {"scan_id": "x"})
        self.assertEqual(error.to_dict(), {"code": "scan_not_found", "message": "missing", "details": {"scan_id": "x"}})
        self.assertIsInstance(error, SCANError)
