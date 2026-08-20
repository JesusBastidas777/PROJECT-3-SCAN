import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import main
from scanner.profiles import apply_profile, PROFILE_VERSION

class ProfileTests(unittest.TestCase):
    def test_exact_expansion_and_version(self):
        parser = main.create_parser(); argv = ["127.0.0.1", "--profile", "minimal"]; args = apply_profile(parser.parse_args(argv), argv)
        self.assertEqual(args.ports, [22, 80, 443]); self.assertEqual(args.workers, 32); self.assertEqual(args.profile_version, PROFILE_VERSION); self.assertFalse(args.collect_tls)
    def test_explicit_overrides_win_and_are_recorded(self):
        argv = ["127.0.0.1", "--profile", "evidence", "--ports", "8080", "--no-collect-tls"]; args = apply_profile(main.create_parser().parse_args(argv), argv)
        self.assertEqual(args.ports, [8080]); self.assertFalse(args.collect_tls); self.assertEqual(args.profile_overrides, ["collect_tls", "ports"])
    def test_legacy_has_no_profile_or_sensitive_enrichment(self):
        argv = ["127.0.0.1"]; args = apply_profile(main.create_parser().parse_args(argv), argv)
        self.assertIsNone(args.profile); self.assertFalse(args.collect_banners); self.assertFalse(args.collect_tls); self.assertFalse(args.resolve_names)
    def test_unknown_profile_is_usage_error(self):
        with self.assertRaises(SystemExit): main.create_parser().parse_args(["127.0.0.1", "--profile", "unknown"])
