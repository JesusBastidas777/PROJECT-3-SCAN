import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scanner.feed import build_feed
from scanner.feed_io import iter_feed_ndjson, write_feed
from test_feed import report


class FeedIoTests(unittest.TestCase):
    def test_json_atomic_and_ndjson_records(self):
        value=build_feed(report())
        lines=list(iter_feed_ndjson(value)); self.assertEqual(len(lines),1+len(value["asset_summaries"])+len(value["endpoint_observations"]))
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"feed.ndjson"; write_feed(value,path,format_name="ndjson"); self.assertEqual(path.read_text().splitlines(),[line.rstrip() for line in lines])
        with patch("sys.stdout",new_callable=io.StringIO) as stdout: write_feed(value,"-",format_name="json"); self.assertIn('"feed_schema_version":"1.0"',stdout.getvalue())
