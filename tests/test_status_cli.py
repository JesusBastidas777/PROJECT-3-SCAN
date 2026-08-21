import io
import os
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import main


class StatusCliTests(unittest.TestCase):
    def test_latest_unavailable_uses_stderr(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"SCAN_RUNTIME_DIR": str(Path(directory) / "runtime")}), patch("sys.stdout", new_callable=io.StringIO) as out, patch("sys.stderr", new_callable=io.StringIO) as err:
            self.assertEqual(main.main(["latest", "--json"]), 2)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("scan_not_found", err.getvalue())
