import io
import json
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from scanner.event_io import event_document, prepare_events, write_events
EVENT = {"event_schema_version":"1.0","event_id":"event_example","event_type":"scan.completed","occurred_at":"2026-01-01T00:00:00.000Z","producer":{"name":"SCAN","version":"2.0.0"},"scan_id":"scan_example","target_id":"target_example","subject":{},"observation":{"text":"sensitive","sha256":"abc"},"evidence_refs":[],"confidence":"observed","limitations":[],"deduplication_key":"dedup_example"}
class EventIoTests(unittest.TestCase):
    def test_byte_exact_ndjson_and_redaction(self):
        values = prepare_events([EVENT], max_event_bytes=16384, privacy="hash-only"); text = event_document(values, "ndjson")
        self.assertEqual(text.count("\n"), 1); self.assertNotIn("sensitive", text); self.assertIn('"sha256":"abc"', text)
    def test_batch_and_legacy_contracts(self):
        legacy = event_document([EVENT], "legacy-json"); batch = event_document([EVENT], "batch-json")
        self.assertEqual(legacy["event_schema_version"], "1.0"); self.assertEqual(batch["batch_schema_version"], "1.0"); self.assertEqual(batch["count"], 1)
    def test_atomic_file_and_stdout(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.ndjson"; write_events([EVENT], path, format_name="ndjson", max_event_bytes=16384, privacy="full"); self.assertEqual(json.loads(path.read_text().splitlines()[0])["event_id"], "event_example")
        with patch("sys.stdout", new_callable=io.StringIO) as stdout: write_events([EVENT], "-", format_name="batch-json", max_event_bytes=16384, privacy="full")
        self.assertEqual(json.loads(stdout.getvalue())["count"], 1)
    def test_validation_and_size_before_write(self):
        with self.assertRaises(ValueError): prepare_events([{}], max_event_bytes=16384, privacy="full")
        with self.assertRaises(ValueError): prepare_events([EVENT], max_event_bytes=256, privacy="full")
    def test_broken_pipe_is_exposed_for_cli_to_handle(self):
        stream = unittest.mock.MagicMock(); stream.write.side_effect = BrokenPipeError()
        with patch("sys.stdout", stream), self.assertRaises(BrokenPipeError):
            write_events([EVENT], "-", format_name="ndjson", max_event_bytes=16384, privacy="full")
