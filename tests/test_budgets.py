import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"src"))
from scanner.budgets import ExecutionBudgets
class BudgetTests(unittest.TestCase):
 def test_exact_reservation_boundary(self):
  b=ExecutionBudgets(max_network_attempts=2); self.assertTrue(b.reserve("network_attempts")); self.assertTrue(b.reserve("network_attempts")); self.assertFalse(b.reserve("network_attempts")); self.assertEqual(b.descriptor("network_attempts","attempts")["remaining"],0)
