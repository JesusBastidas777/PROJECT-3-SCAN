import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"src"))
from scanner.budgets import ExecutionBudgets
from scanner.scheduler import run_scheduled
class SchedulerTests(unittest.TestCase):
 def test_deterministic_prefix_and_bounded_budget(self):
  values,omitted=run_scheduled(lambda x:x*x,iter(range(6)),workers=2,max_pending=2,budgets=ExecutionBudgets(max_network_attempts=3)); self.assertEqual(values,[(0,0),(1,1),(2,4)]); self.assertEqual(omitted,3)
