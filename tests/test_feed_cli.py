import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import main
from test_feed import report


class FeedCliTests(unittest.TestCase):
    def test_offline_json_ndjson_and_corrupt(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"report"; path.write_text(json.dumps(report()),encoding="utf-8")
            for format_name in ("json","ndjson"):
                with patch("sys.stdout",new_callable=io.StringIO) as stdout, patch("main.collect_report") as probe:
                    self.assertEqual(main.main(["feed",str(path),"--feed-format",format_name,"--output","-"]),0); self.assertTrue(stdout.getvalue()); probe.assert_not_called()
            path.write_text("bad",encoding="utf-8")
            with patch("sys.stderr",new_callable=io.StringIO): self.assertEqual(main.main(["feed",str(path)]),1)

    def test_broken_pipe_is_success(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"report"; path.write_text(json.dumps(report()),encoding="utf-8")
            with patch("scanner.commands.feed.write_feed",side_effect=BrokenPipeError): self.assertEqual(main.main(["feed",str(path)]),0)
