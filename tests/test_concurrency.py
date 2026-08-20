import sys
from pathlib import Path
import threading
import time
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from scanner.concurrency import bounded_ordered_calls

class ConcurrencyTests(unittest.TestCase):
    def test_bounded_ordered_and_isolated(self):
        lock = threading.Lock(); running = maximum = 0
        def work(value):
            nonlocal running, maximum
            with lock: running += 1; maximum = max(maximum, running)
            time.sleep(0.005)
            with lock: running -= 1
            if value == 2: raise OSError("isolated")
            return value
        result = bounded_ordered_calls(work, [(x,) for x in range(10)], max_workers=3, max_pending=4)
        self.assertEqual(result[0], 0); self.assertIsInstance(result[2], OSError); self.assertLessEqual(maximum, 3)
