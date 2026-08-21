import os
import sys
from pathlib import Path
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scanner.runtime_paths import SCANRuntimeConfig, default_runtime_dir, prepare_runtime, validate_runtime_root


class RuntimePathTests(unittest.TestCase):
    def test_explicit_runtime_is_absolute_and_cwd_independent(self):
        with tempfile.TemporaryDirectory() as directory:
            expected = Path(directory).resolve()
            self.assertEqual(default_runtime_dir({"SCAN_RUNTIME_DIR": str(expected)}), expected)

    def test_relative_and_source_roots_are_rejected(self):
        with self.assertRaises(ValueError):
            validate_runtime_root(Path("runtime"))
        with self.assertRaises(ValueError):
            validate_runtime_root(Path(__file__).resolve().parents[1] / "runtime")

    def test_layout_and_symlink_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "runtime"
            config = SCANRuntimeConfig(root)
            prepare_runtime(config)
            self.assertTrue(config.readiness_path.parent.is_dir())
            self.assertTrue((config.outbox_dir / "failed").is_dir())
            if hasattr(os, "symlink"):
                link = Path(directory) / "link"
                link.symlink_to(root, target_is_directory=True)
                with self.assertRaises(OSError):
                    prepare_runtime(SCANRuntimeConfig(link))
