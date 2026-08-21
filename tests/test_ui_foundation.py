import os
import sys
from pathlib import Path
import unittest
import io
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from rich.console import Console
from scanner.ui.rendering import build_shell
from scanner.ui.state import UIState
from scanner.ui.theme import INFO, TITLE


class UIFoundationTests(unittest.TestCase):
    def test_exact_semantic_theme_and_deterministic_render(self):
        self.assertEqual(TITLE, "#808000"); self.assertEqual(INFO, "yellow")
        state = UIState(payload={"runtime": "idle", "scan_id": "scan-x"}, status="idle", updated_at="fixed")
        outputs = []
        for _ in range(2):
            stream = io.StringIO(); console = Console(file=stream, no_color=True, width=100)
            console.print(build_shell(state)); outputs.append(stream.getvalue())
        self.assertEqual(outputs[0], outputs[1])

    def test_no_color_console_and_row_bound(self):
        with patch.dict(os.environ, {"NO_COLOR": "1"}):
            console = Console(no_color="NO_COLOR" in os.environ, record=True, width=100)
            console.print(build_shell(UIState(payload={str(i): i for i in range(200)}), max_rows=5))
            exported = console.export_text()
        self.assertNotIn("199", exported)
