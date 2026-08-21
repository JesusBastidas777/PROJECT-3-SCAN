import io
import sys
from pathlib import Path
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import main


class ContractVersionCliTests(unittest.TestCase):
    def test_public_contract_version(self):
        with patch("sys.stdout", new_callable=io.StringIO) as out:
            self.assertEqual(main.main(["contract-version"]), 0)
        self.assertEqual(out.getvalue(), "SCAN public 1.0; report 2.2\n")
