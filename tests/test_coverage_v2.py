import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"src"))
from scanner.coverage import PHASE_ORDER,coverage_v2,phase_descriptor,validate_coverage
class CoverageV2Tests(unittest.TestCase):
 def test_budget_is_omission_not_timeout(self):
  old={"model_version":"1.0","phases":{name:phase_descriptor(name,supported=True,backend="test",enabled=True) for name in PHASE_ORDER}}; old["phases"]["discovery"]=phase_descriptor("discovery",supported=True,backend="test",enabled=True,eligible=2,attempted=1,observed=1,skipped=1,truncated=True)
  value=coverage_v2(old,termination={"reason_code":"budget_exhausted","phase":"discovery","budget_id":"network_attempts"}); validate_coverage(value); p=value["phases"]["discovery"]; self.assertEqual(p["omission_reasons"]["budget_exhausted"],1); self.assertEqual(p["counts"]["timeout"],0)
