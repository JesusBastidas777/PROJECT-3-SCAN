"""Professional command-line interface for SCAN."""

from __future__ import annotations

import argparse
import math
from pathlib import Path
import sys
import time
from collections.abc import Sequence
from typing import Any

from scanner.discovery import (
    DEFAULT_MAX_HOSTS,
    MAX_DISCOVERY_WORKERS,
    TargetValidationError,
    discover_hosts,
    validate_network,
)
from scanner.ports import scan_hosts
from scanner.banners import collect_open_banners, DEFAULT_BANNER_WORKERS, DEFAULT_MAX_BYTES, DEFAULT_MAX_ENDPOINTS
from scanner.report import build_report, serialize_report, utc_timestamp, write_report_atomic

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389]
DEFAULT_WORKERS = 64
DEFAULT_PING_TIMEOUT = 1.0
DEFAULT_CONNECT_TIMEOUT = 1.0
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT_PATH = PROJECT_ROOT / "results" / "scan.json"

EXIT_SUCCESS = 0
EXIT_OPERATIONAL_ERROR = 1
EXIT_USAGE = 2
EXIT_INTERRUPTED = 130


def parse_ports(value: str) -> list[int]:
    """Parse a comma-separated, ordered set of TCP ports for argparse."""

    if not value.strip():
        raise argparse.ArgumentTypeError("ports cannot be empty")
    ports: list[int] = []
    seen: set[int] = set()
    for item in value.split(","):
        try:
            port = int(item.strip())
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"invalid port: {item!r}") from exc
        if not 1 <= port <= 65535:
            raise argparse.ArgumentTypeError(f"port out of range: {port}")
        if port not in seen:
            seen.add(port)
            ports.append(port)
    return ports


def positive_float(value: str) -> float:
    """Parse a positive timeout value."""

    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def worker_count(value: str) -> int:
    """Parse a safe global worker count."""

    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("workers must be an integer") from exc
    if not 1 <= parsed <= MAX_DISCOVERY_WORKERS:
        raise argparse.ArgumentTypeError(
            f"workers must be between 1 and {MAX_DISCOVERY_WORKERS}"
        )
    return parsed


def positive_integer(value: str) -> int:
    """Parse a positive integer."""

    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def create_parser() -> argparse.ArgumentParser:
    """Create the SCAN argument parser."""

    parser = argparse.ArgumentParser(
        prog="SCAN",
        description="Discover hosts and collect structured TCP port scan data.",
    )
    parser.add_argument("target", help="IPv4 or IPv6 address/network in CIDR form")
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT_PATH),
        metavar="PATH|-",
        help="JSON destination; '-' writes JSON only to stdout",
    )
    parser.add_argument(
        "--ports",
        type=parse_ports,
        default=DEFAULT_PORTS,
        metavar="PORTS",
        help="comma-separated TCP ports",
    )
    parser.add_argument(
        "--workers",
        type=worker_count,
        default=DEFAULT_WORKERS,
        help=f"global worker limit (1-{MAX_DISCOVERY_WORKERS})",
    )
    parser.add_argument(
        "--ping-timeout",
        type=positive_float,
        default=DEFAULT_PING_TIMEOUT,
        metavar="SECONDS",
    )
    parser.add_argument(
        "--connect-timeout",
        type=positive_float,
        default=DEFAULT_CONNECT_TIMEOUT,
        metavar="SECONDS",
    )
    parser.add_argument(
        "--max-hosts",
        type=positive_integer,
        default=DEFAULT_MAX_HOSTS,
        metavar="COUNT",
        help="reject targets with more candidate hosts",
    )
    parser.add_argument("--collect-banners", action="store_true", help="passively collect bounded, untrusted banners from open endpoints")
    parser.add_argument("--banner-workers", type=worker_count, default=DEFAULT_BANNER_WORKERS)
    parser.add_argument("--banner-max-endpoints", type=positive_integer, default=DEFAULT_MAX_ENDPOINTS)
    parser.add_argument("--banner-max-bytes", type=positive_integer, default=DEFAULT_MAX_BYTES)
    parser.add_argument("--banner-read-timeout", type=positive_float, default=0.5, metavar="SECONDS")
    return parser


def collect_report(args: argparse.Namespace) -> dict[str, Any]:
    """Acquire scan facts and return a complete schema-v1 report dictionary."""

    network = validate_network(args.target, max_hosts=args.max_hosts)
    timestamp = utc_timestamp()
    started = time.monotonic()
    active_hosts = discover_hosts(
        network,
        timeout=args.ping_timeout,
        max_workers=args.workers,
        max_hosts=args.max_hosts,
    )
    host_results = scan_hosts(
        active_hosts,
        args.ports,
        timeout=args.connect_timeout,
        max_workers=args.workers,
    )
    if args.collect_banners:
        host_results = collect_open_banners(
            host_results, workers=min(args.banner_workers, 32),
            max_endpoints=args.banner_max_endpoints,
            connect_timeout=args.connect_timeout,
            read_timeout=args.banner_read_timeout,
            max_bytes=args.banner_max_bytes,
        )
    duration_ms = max(0, round((time.monotonic() - started) * 1000))
    return build_report(
        target_input=args.target,
        network=network,
        host_port_results=host_results,
        ports=args.ports,
        timestamp=timestamp,
        duration_ms=duration_ms,
        ping_timeout=args.ping_timeout,
        connect_timeout=args.connect_timeout,
        workers=args.workers,
        max_hosts=args.max_hosts,
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Run SCAN and return a documented process exit code."""

    parser = create_parser()
    args = parser.parse_args(argv)
    try:
        report = collect_report(args)
        if args.output == "-":
            sys.stdout.write(serialize_report(report))
        else:
            output_path = Path(args.output).expanduser()
            write_report_atomic(report, output_path)
            print(f"SCAN: report written to {output_path}", file=sys.stderr)
    except TargetValidationError as exc:
        print(f"SCAN: invalid target: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        print("SCAN: interrupted", file=sys.stderr)
        return EXIT_INTERRUPTED
    except (OSError, ValueError) as exc:
        print(f"SCAN: operational error: {exc}", file=sys.stderr)
        return EXIT_OPERATIONAL_ERROR
    except Exception as exc:
        print(f"SCAN: unexpected failure: {exc}", file=sys.stderr)
        return EXIT_OPERATIONAL_ERROR
    return EXIT_SUCCESS


if __name__ == "__main__":
    raise SystemExit(main())
