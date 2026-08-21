import io
import json
import os
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import main


class RuntimeCliTests(unittest.TestCase):
    def test_start_status_stop_are_json(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"SCAN_RUNTIME_DIR": str(Path(directory) / "runtime")}), patch("sys.stdout", new_callable=io.StringIO) as out:
            self.assertEqual(main.main(["runtime", "start"]), 0)
            json.loads(out.getvalue().splitlines()[-1]); out.seek(0); out.truncate(0)
            self.assertEqual(main.main(["status", "--json"]), 0)
            self.assertEqual(json.loads(out.getvalue())["data"]["status"]["lifecycle"], "idle")
            out.seek(0); out.truncate(0)
            self.assertEqual(main.main(["runtime", "stop"]), 0)
            self.assertEqual(json.loads(out.getvalue())["data"]["status"], "stopped")

    def test_readers_do_not_probe(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"SCAN_RUNTIME_DIR": str(Path(directory) / "runtime")}), patch("scanner.scan_pipeline.discover_host_evidence") as probe, patch("sys.stdout", new_callable=io.StringIO):
            main.main(["check"]); main.main(["capabilities", "--json"])
            probe.assert_not_called()
