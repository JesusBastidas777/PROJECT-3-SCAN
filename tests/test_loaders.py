import json
from pathlib import Path
import tempfile
import unittest

from scanner.contract import build_report_v2, build_report_v21
from scanner.loaders import load_report, load_report_or_snapshot
from scanner.snapshots import build_snapshot


def arguments():
    return dict(target_input="127.0.0.1/32",network="127.0.0.1/32",host_results={},ports=[],started_at="2026-01-01T00:00:00.000Z",completed_at="2026-01-01T00:00:00.000Z",duration_ms=0,ping_timeout=1,connect_timeout=1,workers=1,max_hosts=1,banners_enabled=False,banner_limits={})


class LoaderTests(unittest.TestCase):
    def test_version_aware_report_and_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"value.json"
            for report in (build_report_v2(**arguments()), build_report_v21(**arguments())):
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertEqual(load_report(path)["schema_version"], report["schema_version"])
                path.write_text(json.dumps(build_snapshot(report)), encoding="utf-8")
                loaded, snapshot = load_report_or_snapshot(path)
                self.assertEqual(loaded["schema_version"], report["schema_version"]); self.assertIsNotNone(snapshot)

    def test_corrupt_unknown_oversized_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"x"; path.write_text("bad",encoding="utf-8")
            with self.assertRaises(json.JSONDecodeError): load_report(path)
            path.write_text('{}',encoding="utf-8")
            with self.assertRaises(ValueError): load_report(path)
            with self.assertRaises(OSError): load_report(path,max_bytes=1)
            link=Path(directory)/"link"; link.symlink_to(path)
            with self.assertRaises(OSError): load_report(link)
