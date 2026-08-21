"""Professional command-line interface for SCAN."""

from __future__ import annotations

import argparse
import json
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
    discover_host_evidence,
    validate_network,
)
from scanner.ports import scan_hosts
from scanner.banners import collect_open_banners, DEFAULT_BANNER_WORKERS, DEFAULT_MAX_BYTES, DEFAULT_MAX_ENDPOINTS
from scanner.report import build_report, serialize_report, utc_timestamp, write_report_atomic
from scanner.contract import SUPPORTED_REPORT_VERSIONS, build_report_v2, build_report_v21
from scanner.snapshots import save_snapshot
from scanner.events import events_from_report
from scanner.discovery_tcp import collect_tcp_discovery, responsive_addresses, reusable_endpoint_observations
from scanner.tls import collect_open_tls, DEFAULT_TLS_PORTS, MAX_TLS_WORKERS
from scanner.dns import collect_name_observations, MAX_DNS_WORKERS
from scanner.retention import retain_snapshots
from scanner.commands.compare import compare_main
from scanner.profiles import apply_profile, PROFILES
from scanner.event_io import write_events
from scanner.events import MAX_EVENT_BYTES

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389]
DEFAULT_WORKERS = 64
DEFAULT_PING_TIMEOUT = 1.0
DEFAULT_CONNECT_TIMEOUT = 1.0
MAX_PORTS = 1024
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
        if len(ports) > MAX_PORTS:
            raise argparse.ArgumentTypeError(f"no more than {MAX_PORTS} unique ports are allowed")
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


def banner_worker_count(value: str) -> int:
    parsed = positive_integer(value)
    if parsed > 32:
        raise argparse.ArgumentTypeError("banner workers must be between 1 and 32")
    return parsed


def banner_byte_limit(value: str) -> int:
    parsed = positive_integer(value)
    if parsed > 65536:
        raise argparse.ArgumentTypeError("banner bytes must be between 1 and 65536")
    return parsed


def tls_worker_count(value: str) -> int:
    parsed = positive_integer(value)
    if parsed > MAX_TLS_WORKERS:
        raise argparse.ArgumentTypeError(f"TLS workers must be between 1 and {MAX_TLS_WORKERS}")
    return parsed


def dns_worker_count(value: str) -> int:
    parsed = positive_integer(value)
    if parsed > MAX_DNS_WORKERS:
        raise argparse.ArgumentTypeError(f"DNS workers must be between 1 and {MAX_DNS_WORKERS}")
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
    parser.add_argument("--collect-banners", action=argparse.BooleanOptionalAction, default=False, help="passively collect bounded, untrusted banners from open endpoints")
    parser.add_argument("--banner-workers", type=banner_worker_count, default=DEFAULT_BANNER_WORKERS)
    parser.add_argument("--banner-max-endpoints", type=positive_integer, default=DEFAULT_MAX_ENDPOINTS)
    parser.add_argument("--banner-max-bytes", type=banner_byte_limit, default=DEFAULT_MAX_BYTES)
    parser.add_argument("--banner-read-timeout", type=positive_float, default=0.5, metavar="SECONDS")
    parser.add_argument("--schema-version", choices=SUPPORTED_REPORT_VERSIONS, default="1.0")
    parser.add_argument("--history-dir", type=Path, help="opt-in immutable snapshot directory (schema 2.0 only)")
    parser.add_argument("--lock-timeout", type=positive_float, default=5.0, metavar="SECONDS")
    parser.add_argument("--events-output", type=Path, help="write bounded FOREX event array (schema 2.0 only)")
    parser.add_argument("--max-events", type=positive_integer, default=256)
    parser.add_argument("--events-format", choices=("legacy-json", "batch-json", "ndjson"), default="legacy-json")
    parser.add_argument("--max-event-bytes", type=positive_integer, default=MAX_EVENT_BYTES)
    parser.add_argument("--events-privacy", choices=("full", "hash-only"), default="full")
    parser.add_argument("--discovery", choices=("icmp", "icmp-tcp", "tcp"), default="icmp")
    parser.add_argument("--discovery-ports", type=parse_ports, default=[443, 80, 22], metavar="PORTS")
    parser.add_argument("--discovery-connect-timeout", type=positive_float, default=0.5, metavar="SECONDS")
    parser.add_argument("--max-discovery-endpoints", type=positive_integer, default=4096, metavar="COUNT")
    parser.add_argument("--collect-tls", action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument("--tls-ports", type=parse_ports, default=list(DEFAULT_TLS_PORTS), metavar="PORTS")
    parser.add_argument("--tls-workers", type=tls_worker_count, default=4)
    parser.add_argument("--tls-max-endpoints", type=positive_integer, default=32)
    parser.add_argument("--tls-connect-timeout", type=positive_float, default=.5, metavar="SECONDS")
    parser.add_argument("--tls-handshake-timeout", type=positive_float, default=1.0, metavar="SECONDS")
    parser.add_argument("--resolve-names", action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument("--dns-workers", type=dns_worker_count, default=4)
    parser.add_argument("--dns-timeout", type=positive_float, default=1.0, metavar="SECONDS")
    parser.add_argument("--dns-max-assets", type=positive_integer, default=256)
    parser.add_argument("--profile", choices=tuple(PROFILES))
    return parser


def collect_report(args: argparse.Namespace) -> dict[str, Any]:
    """Acquire scan facts and return a complete schema-v1 report dictionary."""

    network = validate_network(args.target, max_hosts=args.max_hosts)
    timestamp = utc_timestamp()
    started = time.monotonic()
    discovery_mode = getattr(args, "discovery", "icmp")
    discovery_observations = [] if discovery_mode == "tcp" else discover_host_evidence(network, timeout=args.ping_timeout, max_workers=args.workers, max_hosts=args.max_hosts)
    candidates = [str(address) for address in network.hosts()]
    if discovery_mode == "icmp-tcp":
        candidates = [item["address"] for item in discovery_observations if item["result"] != "response"]
    tcp_discovery = []
    if discovery_mode in {"icmp-tcp", "tcp"}:
        tcp_discovery = collect_tcp_discovery(candidates, getattr(args, "discovery_ports", [443, 80, 22]), timeout=getattr(args, "discovery_connect_timeout", 0.5), max_workers=args.workers, max_endpoints=getattr(args, "max_discovery_endpoints", 4096))
        discovery_observations.extend(tcp_discovery)
    active_hosts = responsive_addresses(discovery_observations)
    host_results = scan_hosts(
        active_hosts,
        args.ports,
        timeout=args.connect_timeout,
        max_workers=args.workers,
    )
    reusable = reusable_endpoint_observations(tcp_discovery)
    for host, observations in host_results.items():
        host_results[host] = [reusable.get((host, int(item["port"])), item) for item in observations]
    if getattr(args, "collect_tls", False):
        host_results = collect_open_tls(host_results, ports=args.tls_ports, workers=args.tls_workers, max_endpoints=args.tls_max_endpoints, connect_timeout=args.tls_connect_timeout, handshake_timeout=args.tls_handshake_timeout)
    name_observations = collect_name_observations(active_hosts, workers=args.dns_workers, timeout=args.dns_timeout, max_assets=args.dns_max_assets) if getattr(args, "resolve_names", False) else []
    if args.collect_banners:
        host_results = collect_open_banners(
            host_results, workers=min(args.banner_workers, 32),
            max_endpoints=args.banner_max_endpoints,
            connect_timeout=args.connect_timeout,
            read_timeout=args.banner_read_timeout,
            max_bytes=args.banner_max_bytes,
        )
    duration_ms = max(0, round((time.monotonic() - started) * 1000))
    if args.schema_version in {"2.0", "2.1"}:
        completed_at = utc_timestamp()
        builder = build_report_v21 if args.schema_version == "2.1" else build_report_v2
        return builder(
            target_input=args.target, network=network, host_results=host_results,
            ports=args.ports, started_at=timestamp, completed_at=completed_at,
            duration_ms=duration_ms, ping_timeout=args.ping_timeout,
            connect_timeout=args.connect_timeout, workers=args.workers,
            max_hosts=args.max_hosts, banners_enabled=args.collect_banners,
            banner_limits={"workers": min(args.banner_workers, 32), "max_endpoints": args.banner_max_endpoints, "max_bytes": args.banner_max_bytes, "read_timeout_seconds": args.banner_read_timeout},
            discovery_observations=discovery_observations,
            discovery_configuration={"mode": discovery_mode, "ports": getattr(args, "discovery_ports", [443, 80, 22]), "connect_timeout_seconds": getattr(args, "discovery_connect_timeout", 0.5), "max_endpoints": getattr(args, "max_discovery_endpoints", 4096)},
            tls_configuration={"enabled": getattr(args, "collect_tls", False), "ports": getattr(args, "tls_ports", list(DEFAULT_TLS_PORTS)), "workers": getattr(args, "tls_workers", 4), "max_endpoints": getattr(args, "tls_max_endpoints", 32), "connect_timeout_seconds": getattr(args, "tls_connect_timeout", .5), "handshake_timeout_seconds": getattr(args, "tls_handshake_timeout", 1.0)},
            name_observations=name_observations,
            dns_configuration={"enabled": getattr(args, "resolve_names", False), "workers": getattr(args, "dns_workers", 4), "timeout_seconds": getattr(args, "dns_timeout", 1.0), "timeout_guarantee": "best_effort", "max_assets": getattr(args, "dns_max_assets", 256)},
            profile_configuration={"name": getattr(args, "profile", None), "version": getattr(args, "profile_version", None), "overrides": getattr(args, "profile_overrides", [])},
        )
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

    arguments = list(argv) if argv is not None else sys.argv[1:]
    if arguments[:1] == ["compare"]:
        return compare_main(arguments[1:])
    if arguments[:2] == ["history", "retain"]:
        return history_retain_main(arguments[2:])
    if arguments[:1] == ["scan"]:
        arguments = arguments[1:]
    parser = create_parser()
    args = apply_profile(parser.parse_args(arguments), arguments)
    try:
        report = collect_report(args)
        if args.history_dir is not None:
            if args.schema_version != "2.0":
                raise ValueError("--history-dir requires --schema-version 2.0")
            _, snapshot_path = save_snapshot(report, args.history_dir, lock_timeout=args.lock_timeout)
            print(f"SCAN: snapshot written to {snapshot_path}", file=sys.stderr)
        if args.events_output is not None:
            if args.schema_version != "2.0":
                raise ValueError("--events-output requires --schema-version 2.0")
            if str(args.events_output) == "-" and args.output == "-":
                raise ValueError("report and events cannot both use stdout")
            write_events(events_from_report(report, max_events=args.max_events), args.events_output, format_name=args.events_format, max_event_bytes=args.max_event_bytes, privacy=args.events_privacy)
            print(f"SCAN: events written to {args.events_output}", file=sys.stderr)
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
    except BrokenPipeError:
        return EXIT_SUCCESS
    except (OSError, ValueError) as exc:
        print(f"SCAN: operational error: {exc}", file=sys.stderr)
        return EXIT_OPERATIONAL_ERROR
    except Exception as exc:
        print(f"SCAN: unexpected failure: {exc}", file=sys.stderr)
        return EXIT_OPERATIONAL_ERROR
    return EXIT_SUCCESS


def history_retain_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="SCAN history retain")
    parser.add_argument("--history-dir", type=Path, required=True)
    parser.add_argument("--keep-last", type=positive_integer)
    parser.add_argument("--max-age-days", type=positive_integer)
    parser.add_argument("--lock-timeout", type=positive_float, default=5.0)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    if args.apply and args.dry_run:
        parser.error("--apply and --dry-run are mutually exclusive")
    try:
        result = retain_snapshots(args.history_dir, keep_last=args.keep_last, max_age_days=args.max_age_days, dry_run=not args.apply, lock_timeout=args.lock_timeout)
        sys.stdout.write(serialize_report(result))
        return EXIT_SUCCESS
    except (OSError, ValueError, TimeoutError, json.JSONDecodeError) as exc:
        print(f"SCAN: operational error: {exc}", file=sys.stderr)
        return EXIT_OPERATIONAL_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
