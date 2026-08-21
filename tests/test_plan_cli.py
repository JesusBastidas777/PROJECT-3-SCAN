import io,json,unittest,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"src"))
from unittest.mock import patch
import main
class PlanCliTests(unittest.TestCase):
 def test_json_stdout_and_zero_acquisition(self):
  with patch("scanner.scan_pipeline.execute_scan",side_effect=AssertionError("probe")),patch("scanner.discovery.discover_host_evidence",side_effect=AssertionError("probe")),patch("sys.stdout",new_callable=io.StringIO) as out:
   self.assertEqual(main.main(["plan","127.0.0.1/32","--output","-"]),0); self.assertEqual(json.loads(out.getvalue())["document_type"],"scan_plan")
 def test_large_target_rejected_without_history(self):
  with patch("sys.stderr",new_callable=io.StringIO): self.assertEqual(main.main(["plan","0.0.0.0/0","--max-hosts","4"]),2)
