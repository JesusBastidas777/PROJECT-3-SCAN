"""Command-line entry point for SCAN."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
from collections.abc import Sequence

from scanner.discovery import TargetValidationError, discover_hosts, normalize_network
from scanner.ports import scan_hosts

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389]
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT_PATH = PROJECT_ROOT / "results" / "scan.json"

EXIT_SUCCESS = 0
EXIT_USAGE = 2
EXIT_OPERATIONAL_ERROR = 1
EXIT_INTERRUPTED = 130


def build_scan_data(network: str, active_hosts: list[str]) -> dict[str, object]:
    """Scan active hosts and build the legacy JSON-compatible structure."""

    host_port_results = scan_hosts(active_hosts, DEFAULT_PORTS)
    scan_results: list[dict[str, object]] = []
    total_open_ports = 0
    total_closed_ports = 0

    for host in active_hosts:
        ports = host_port_results.get(host, [])
        open_ports = [result["port"] for result in ports if result["status"] == "OPEN"]
        open_count = len(open_ports)
        closed_count = len(ports) - open_count
        total_open_ports += open_count
        total_closed_ports += closed_count
        scan_results.append(
            {
                "host": host,
                "ports": ports,
                "open_ports": open_ports,
                "open_count": open_count,
                "closed_count": closed_count,
            }
        )

    return {
        "network": network,
        "summary": {
            "active_hosts": len(active_hosts),
            "total_open_ports": total_open_ports,
            "total_closed_ports": total_closed_ports,
        },
        "hosts": scan_results,
    }


def write_json_atomic(data: dict[str, object], output_path: Path) -> None:
    """Write JSON beside its destination and atomically replace the final file."""

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output_path.parent,
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            json.dump(data, temporary_file, indent=4)
            temporary_file.write("\n")
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_path, output_path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass


def run_scan(network: str, output_path: Path = DEFAULT_OUTPUT_PATH) -> dict[str, object]:
    """Run discovery and scanning, then atomically persist the legacy report."""

    normalized_network = str(normalize_network(network))
    active_hosts = discover_hosts(normalized_network)
    scan_data = build_scan_data(normalized_network, active_hosts)
    write_json_atomic(scan_data, output_path)
    return scan_data


def main(argv: Sequence[str] | None = None) -> int:
    """Run the existing one-target CLI and return a process exit code."""

    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1:
        print("Usage: python3 src/main.py <network>", file=sys.stderr)
        return EXIT_USAGE

    network = arguments[0]
    print("Network Scanner")
    print(f"Target Network: {network}")

    try:
        scan_data = run_scan(network)
    except TargetValidationError as exc:
        print(f"Invalid target: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        print("Scan interrupted.", file=sys.stderr)
        return EXIT_INTERRUPTED
    except (OSError, ValueError) as exc:
        print(f"Scan failed: {exc}", file=sys.stderr)
        return EXIT_OPERATIONAL_ERROR
    except Exception as exc:
        print(f"Unexpected scan failure: {exc}", file=sys.stderr)
        return EXIT_OPERATIONAL_ERROR

    for host_result in scan_data["hosts"]:
        print(f"Scanning host: {host_result['host']}")
        for result in host_result["ports"]:
            print(f"{result['port']}/{result['protocol']}\t{result['status']}")

    print(f"Results saved to {DEFAULT_OUTPUT_PATH}")
    print("Active Hosts:")
    for host in (host["host"] for host in scan_data["hosts"]):
        print(host)
    return EXIT_SUCCESS


if __name__ == "__main__":
    raise SystemExit(main())
