import io
import json
import sys
from pathlib import Path
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import main

class CliEndToEndTests(unittest.TestCase):
    def test_v2_stdout_is_one_json_document(self):
        with patch("scanner.scan_pipeline.discover_host_evidence", return_value=[]), patch("sys.stdout", new_callable=io.StringIO) as stdout, patch("sys.stderr", new_callable=io.StringIO) as stderr:
            code = main.main(["127.0.0.1/32", "--schema-version", "2.0", "--output", "-"])
        self.assertEqual(code, 0); self.assertEqual(json.loads(stdout.getvalue())["schema_version"], "2.0"); self.assertEqual(stderr.getvalue(), "")

    def test_history_with_v1_is_rejected(self):
        with patch("main.collect_report", return_value={}), patch("sys.stderr", new_callable=io.StringIO):
            self.assertEqual(main.main(["127.0.0.1/32", "--history-dir", "history"]), main.EXIT_OPERATIONAL_ERROR)
