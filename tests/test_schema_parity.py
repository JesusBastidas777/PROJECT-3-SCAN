import json, sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class SchemaParityTests(unittest.TestCase):
    def test_public_schema_versions_and_required_fields_match_registry(self):
        root = Path(__file__).resolve().parents[1]
        expected = {"scan-readiness-1.0.schema.json": ("readiness_schema_version", "1.0"), "scan-heartbeat-1.0.schema.json": ("heartbeat_schema_version", "1.0"), "scan-runtime-status-1.0.schema.json": ("status_schema_version", "1.0"), "scan-operational-view-1.0.schema.json": ("operational_view_schema_version", "1.0")}
        from scanner.contract_registry import REGISTRY
        for filename, (field, version) in expected.items():
            schema = json.loads((root / "schemas" / filename).read_text())
            self.assertIn(field, schema["required"]); self.assertEqual(schema["properties"][field]["const"], version)
        for kind in ("readiness", "heartbeat", "runtime_status", "operational_view"):
            self.assertIn((kind, "1.0"), REGISTRY)
