import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import main
from scanner.contract import build_report_v2


def report():
    return build_report_v2(target_input="127.0.0.1/32",network="127.0.0.1/32",host_results={},ports=[],started_at="2026-01-01T00:00:00.000Z",completed_at="2026-01-01T00:00:00.000Z",duration_ms=0,ping_timeout=1,connect_timeout=1,workers=1,max_hosts=1,banners_enabled=False,banner_limits={})


class QueryCliTests(unittest.TestCase):
    def test_json_ndjson_text_and_zero_probes(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"report.json"; path.write_text(json.dumps(report()),encoding="utf-8")
            for format_name in ("json","ndjson","text"):
                with self.subTest(format=format_name), patch("sys.stdout",new_callable=io.StringIO) as stdout, patch("main.collect_report") as probe:
                    self.assertEqual(main.main(["query",str(path),"--open-endpoints","--output",format_name]),0); probe.assert_not_called(); self.assertIsInstance(stdout.getvalue(),str)

    def test_corrupt_oversized_symlink_and_exit_code(self):
        with tempfile.TemporaryDirectory() as directory, patch("sys.stderr",new_callable=io.StringIO):
            path=Path(directory)/"bad"; path.write_text("bad",encoding="utf-8")
            self.assertEqual(main.main(["query",str(path)]),1)
            path.write_text(json.dumps(report()),encoding="utf-8")
            self.assertEqual(main.main(["query",str(path),"--max-input-bytes","1"]),1)
            link=Path(directory)/"link"; link.symlink_to(path); self.assertEqual(main.main(["query",str(link)]),1)

    def test_history_list_and_traversal_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); (root/"index.json").write_text(json.dumps({"version":"1.0","targets":{"target_aaaaaaaaaaaaaaaaaaaa":[]}}))
            with patch("sys.stdout",new_callable=io.StringIO) as stdout:
                self.assertEqual(main.main(["history","list","--history-dir",str(root)]),0); self.assertIn("target_",stdout.getvalue())
            with patch("sys.stderr",new_callable=io.StringIO):
                self.assertEqual(main.main(["history","show","--history-dir",str(root),"--target","../bad","--snapshot","snapshot_"+"a"*24]),1)
