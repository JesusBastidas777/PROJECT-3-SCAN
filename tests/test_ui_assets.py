import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from scanner.ui.screens.assets import render as assets
from scanner.ui.screens.endpoints import render as endpoints


class UIAssetTests(unittest.TestCase):
    def test_assets_and_hint_semantics(self):
        self.assertEqual(assets({"assets": []}).row_count, 1)
        view = endpoints({"endpoints": [{"asset_id": "a", "port": 443, "state": "open", "service_hint": {"name": "https"}}]})
        self.assertEqual(view.row_count, 1)
