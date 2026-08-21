import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import MagicMock, patch

from scanner.neighbors import LinuxIpNeighborBackend, LinuxProcArpBackend, UnsupportedNeighborBackend, WindowsPowerShellNeighborBackend, collect_neighbor_evidence
from scanner.platform_context import network_context

FIXTURES = Path(__file__).parent / "fixtures" / "neighbors"


class NeighborTests(unittest.TestCase):
    def test_linux_json_fixed_argv_no_shell_and_hash_only(self):
        completed = MagicMock(returncode=0, stdout=(FIXTURES / "linux-ip.json").read_text())
        with patch("scanner.neighbors.subprocess.run", return_value=completed) as run:
            values, execution = collect_neighbor_evidence("192.168.1.0/24", backend=LinuxIpNeighborBackend(), context="linux_host")
        self.assertEqual(run.call_args.args[0], ["ip", "-j", "neighbor", "show"])
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertEqual(execution["observed"], 1)
        self.assertIn("link_layer_sha256", values[0]); self.assertNotIn("link_layer_address", values[0])
        self.assertFalse(values[0]["active_probe"])

    def test_full_privacy_limit_and_deterministic_filtering(self):
        backend = MagicMock(name="fixture"); backend.name = "fixture"
        backend.read.return_value = [
            {"address":"192.168.1.3","interface":"eth1","link_layer_address":"00-11-22-33-44-66","neighbor_state":"stale"},
            {"address":"192.168.1.2","interface":"eth0","link_layer_address":"aa:bb:cc:dd:ee:ff","neighbor_state":"reachable"},
            {"address":"203.0.113.1","interface":"eth0"},
        ]
        values, execution = collect_neighbor_evidence("192.168.1.0/24", backend=backend, privacy="full", max_records=1, context="linux_host")
        self.assertEqual(values[0]["address"], "192.168.1.2")
        self.assertEqual(values[0]["link_layer_address"], "aa:bb:cc:dd:ee:ff")
        self.assertTrue(execution["truncated"])

    def test_proc_arp_and_windows_structured_backends(self):
        values = LinuxProcArpBackend(FIXTURES / "proc-arp.txt").read(1)
        self.assertEqual(values[0]["address"], "192.168.1.4")
        completed = MagicMock(returncode=0, stdout=(FIXTURES / "windows.json").read_text())
        with patch("scanner.neighbors.subprocess.run", return_value=completed) as run:
            windows = WindowsPowerShellNeighborBackend().read(1)
        self.assertEqual(windows[0]["interface"], "Ethernet")
        self.assertFalse(run.call_args.kwargs["shell"])

    def test_unsupported_timeout_permission_and_outside_link(self):
        values, execution = collect_neighbor_evidence("192.168.1.0/24", backend=UnsupportedNeighborBackend(), context="x")
        self.assertEqual(values, []); self.assertFalse(execution["supported"])
        backend = MagicMock(); backend.name = "mock"; backend.read.side_effect = subprocess.TimeoutExpired("ip", 1)
        self.assertEqual(collect_neighbor_evidence("192.168.1.0/24", backend=backend, context="x")[1]["timeout"], 1)
        backend.read.side_effect = PermissionError()
        self.assertEqual(collect_neighbor_evidence("192.168.1.0/24", backend=backend, context="x")[1]["reason"], "permission_denied")
        backend.read.reset_mock()
        self.assertEqual(collect_neighbor_evidence("8.8.8.0/24", backend=backend, context="x")[1]["reason"], "target_not_on_link")
        backend.read.assert_not_called()

    def test_ipv6_link_local_scope_and_wsl_context(self):
        backend = MagicMock(); backend.name = "mock"; backend.read.return_value = [{"address":"fe80::2","interface":"eth0","link_layer_address":"00:11:22:33:44:55","neighbor_state":"stale"}]
        values, _ = collect_neighbor_evidence("fe80::/64", backend=backend, interface="eth0", context="wsl_guest")
        self.assertEqual(values[0]["ip_version"], 6); self.assertEqual(values[0]["interface"], "eth0")
        self.assertEqual(network_context(system="Linux", release_text="microsoft-standard-WSL2"), "wsl_guest")

    def test_malformed_output_falls_back_without_active_network(self):
        completed = MagicMock(returncode=0, stdout="not-json")
        with patch("scanner.neighbors.subprocess.run", return_value=completed), patch("scanner.neighbors.LinuxProcArpBackend.read", return_value=[]):
            values, execution = collect_neighbor_evidence("192.168.1.0/24", backend=LinuxIpNeighborBackend(), context="linux_host")
        self.assertEqual(values, []); self.assertEqual(execution["backend"], "linux_proc_arp")
