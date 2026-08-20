import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from scanner.findings import findings_from_report


class FindingTests(unittest.TestCase):
    def test_allowed_facts_and_no_prohibited_claims(self):
        report = {"observations": [{"asset_id": "a", "observation_id": "o", "port": 80, "transport": "tcp", "state": "open"}, {"asset_id": "a", "observation_id": "e", "port": 81, "transport": "tcp", "state": "unknown"}]}
        text = " ".join(item["statement"] for item in findings_from_report(report)).lower()
        self.assertIn("accepted a connection", text)
        self.assertIn("inconclusive", text)
        for forbidden in ("vulnerable", "compromised", "firewall", "cve", "critical risk", "os confirmed"):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
