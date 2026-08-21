import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"src"))
from scanner.resume import acquisition_provenance,validate_resume
class ResumeTests(unittest.TestCase):
 def test_explicit_compatibility_and_temporal_provenance(self):
  checkpoint={"target":{"target_id":"t"},"measurement_scope_fingerprint":"m","execution_policy_fingerprint":"e"}; validate_resume(checkpoint,target_id="t",measurement_scope_fingerprint="m",execution_policy_fingerprint="e")
  with self.assertRaises(ValueError): validate_resume(checkpoint,target_id="other",measurement_scope_fingerprint="m",execution_policy_fingerprint="e")
  value=acquisition_provenance(started_at="2026-01-02T00:00:00Z",completed_at="2026-01-02T00:00:01Z",resumed_from="checkpoint_x",previous_segments=[{"acquisition_segment_id":"old","started_at":"2026-01-01T00:00:00Z","completed_at":"2026-01-01T00:00:01Z","source":"checkpoint"}]); self.assertFalse(value["temporally_uniform"]); self.assertEqual(value["mode"],"resumed")
