import sys
from pathlib import Path
import unittest
from unittest.mock import Mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from scanner.integrations.forex import FOREXSCANWorkflow
from scanner.models import SCANResponseV1


class UIActionTests(unittest.TestCase):
    def test_start_requires_exact_prior_plan(self):
        service = Mock(); service.plan_scan.return_value = SCANResponseV1(data={"plan": {}}); service.start_scan.return_value = SCANResponseV1()
        workflow = FOREXSCANWorkflow(service)
        request = object()
        with self.assertRaises(ValueError): workflow.start(request)
        workflow.plan(request); workflow.start(request)
        service.start_scan.assert_called_once_with(request)
