import json
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scanner.contract import build_report_v2
from scanner.snapshots import build_snapshot, save_snapshot


def report():
    return build_report_v2(target_input="127.0.0.1/32", network="127.0.0.1/32", host_results={}, ports=[], started_at="2026-08-20T00:00:00.000Z", completed_at="2026-08-20T00:00:01.000Z", duration_ms=1000, ping_timeout=1.0, connect_timeout=1.0, workers=1, max_hosts=1, banners_enabled=False, banner_limits={})


class SnapshotTests(unittest.TestCase):
    def test_save_is_atomic_indexed_and_immutable(self):
        with tempfile.TemporaryDirectory() as directory:
            snapshot, path = save_snapshot(report(), Path(directory))
            self.assertEqual(json.loads(path.read_text())["snapshot_id"], snapshot["snapshot_id"])
            self.assertTrue((Path(directory) / "index.json").exists())
            with self.assertRaises(FileExistsError):
                save_snapshot(report(), Path(directory))

    def test_corrupt_index_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "index.json").write_text("not-json")
            with self.assertRaises(OSError):
                save_snapshot(report(), Path(directory))

    def test_volatile_fields_do_not_change_content_fingerprint(self):
        first = report()
        second = report()
        second["duration_ms"] = 999
        second["completed_at"] = "2026-08-21T00:00:00.000Z"
        self.assertEqual(build_snapshot(first)["content_fingerprint"], build_snapshot(second)["content_fingerprint"])

    def test_target_input_cannot_escape_root(self):
        value = report()
        value["target"]["input"] = "../../outside"
        with tempfile.TemporaryDirectory() as directory:
            _, path = save_snapshot(value, Path(directory))
            self.assertTrue(path.resolve().is_relative_to(Path(directory).resolve()))

    def test_partial_index_failure_removes_new_snapshot(self):
        with tempfile.TemporaryDirectory() as directory, patch("scanner.snapshots._atomic_json", side_effect=OSError("disk")):
            with self.assertRaises(OSError):
                save_snapshot(report(), Path(directory))
            self.assertEqual(list(Path(directory).glob("target_*/*.json")), [])

    def test_schema_one_cannot_be_snapshotted(self):
        with self.assertRaises(ValueError):
            build_snapshot({"schema_version": "1.0"})


if __name__ == "__main__":
    unittest.main()
