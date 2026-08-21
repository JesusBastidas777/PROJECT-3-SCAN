import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import scanner


class FOREXConsumerContractTests(unittest.TestCase):
    def test_consumer_boundary_is_narrow(self):
        self.assertEqual(set(scanner.__all__), {"FOREXSCANWorkflow", "SCANConfig", "SCANError", "SCANResponseV1", "SCANService"})
