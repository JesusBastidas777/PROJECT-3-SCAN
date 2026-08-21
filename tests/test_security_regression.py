import sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from scanner.scan_parser import create_parser
from scanner.runtime_paths import default_runtime_dir, SOURCE_ROOT


class SecurityRegressionTests(unittest.TestCase):
    def test_legacy_default_bounds_and_runtime_separation(self):
        args = create_parser().parse_args(["127.0.0.1/32"])
        self.assertEqual(args.schema_version, "1.0"); self.assertLessEqual(args.workers, 256); self.assertGreater(args.max_hosts, 0)
        with self.assertRaises(ValueError): default_runtime_dir({}).resolve().relative_to(SOURCE_ROOT.resolve())

    def test_no_remote_server_or_broker_dependencies(self):
        text = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text().lower()
        for name in ("grpc", "redis", "kafka", "rabbitmq", "websocket"):
            self.assertNotIn(name, text)
