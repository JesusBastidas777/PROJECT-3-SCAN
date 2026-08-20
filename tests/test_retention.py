import json
import multiprocessing
import sys
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from scanner.contract import build_report_v2
from scanner.retention import retain_snapshots
from scanner.snapshots import save_snapshot

def report(timestamp):
    return build_report_v2(target_input="127.0.0.1/32", network="127.0.0.1/32", host_results={}, ports=[], started_at=timestamp, completed_at=timestamp, duration_ms=0, ping_timeout=1, connect_timeout=1, workers=1, max_hosts=1, banners_enabled=False, banner_limits={})

def save_in_process(root, timestamp, queue):
    try:
        queue.put(save_snapshot(report(timestamp), Path(root))[0]["snapshot_id"])
    except Exception as exc:
        queue.put(type(exc).__name__)

class RetentionTests(unittest.TestCase):
    def test_multiprocess_writes_preserve_both_index_updates(self):
        with tempfile.TemporaryDirectory() as directory:
            queue = multiprocessing.Queue()
            processes = [multiprocessing.Process(target=save_in_process, args=(directory, f"2026-01-0{day}T00:00:00.000Z", queue)) for day in (1, 2)]
            try:
                for process in processes: process.start()
            except PermissionError:
                for process in processes:
                    if process.is_alive(): process.terminate()
                self.skipTest("sandbox prohibits multiprocessing IPC sockets")
            for process in processes: process.join(3)
            identifiers = {queue.get(timeout=1), queue.get(timeout=1)}
            index = json.loads((Path(directory) / "index.json").read_text())
            self.assertEqual(set(next(iter(index["targets"].values()))), identifiers)
    def test_dry_run_then_apply_keep_last(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); first = save_snapshot(report("2026-01-01T00:00:00.000Z"), root)[0]; second = save_snapshot(report("2026-01-02T00:00:00.000Z"), root)[0]
            plan = retain_snapshots(root, keep_last=1)
            self.assertTrue(plan["dry_run"]); self.assertIn(first["snapshot_id"], plan["removed_snapshot_ids"])
            self.assertTrue((root / first["target_id"] / f"{first['snapshot_id']}.json").exists())
            retain_snapshots(root, keep_last=1, dry_run=False)
            index = json.loads((root / "index.json").read_text())
            self.assertEqual(index["targets"][second["target_id"]], [second["snapshot_id"]])
    def test_max_age_and_missing_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); value = save_snapshot(report("2026-01-01T00:00:00.000Z"), root)[0]
            plan = retain_snapshots(root, max_age_days=1, now=datetime(2026, 1, 3, tzinfo=timezone.utc))
            self.assertIn(value["snapshot_id"], plan["removed_snapshot_ids"])
            with self.assertRaises(ValueError): retain_snapshots(root)
