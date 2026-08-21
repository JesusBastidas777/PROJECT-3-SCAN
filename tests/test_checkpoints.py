import sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"src"))
from scanner.checkpoints import build_checkpoint,load_checkpoint,save_checkpoint,stable_work_unit_id
class CheckpointTests(unittest.TestCase):
 def test_separate_atomic_roundtrip_and_duplicate_rejection(self):
  unit={"work_unit_id":stable_work_unit_id({"host":"::1","port":443}),"host":"::1","port":443}; value=build_checkpoint(target={"target_id":"target_x"},measurement_scope_fingerprint="m",execution_policy_fingerprint="e",configuration={},completed=[unit],pending=[],evidence=[],privacy="hash-only")
  with tempfile.TemporaryDirectory() as d: path=save_checkpoint(value,Path(d)); self.assertEqual(load_checkpoint(path)["provenance"]["kind"],"operational_checkpoint_not_snapshot")
