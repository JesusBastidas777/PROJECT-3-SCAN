import os
import sys
from pathlib import Path
import tempfile
import time
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from scanner.locking import FileLock

class LockingTests(unittest.TestCase):
    def test_contention_times_out_and_release_cleans(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock"
            with FileLock(path, timeout=.1):
                with self.assertRaises(TimeoutError):
                    with FileLock(path, timeout=.01): pass
            self.assertFalse(path.exists())
    def test_stale_lock_is_recovered(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock"; path.write_text("stale")
            os.utime(path, (time.time() - 10, time.time() - 10))
            with FileLock(path, timeout=.1, stale_after=1): self.assertTrue(path.exists())
