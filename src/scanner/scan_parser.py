"""Argument parsing for the SCAN acquisition command."""
from __future__ import annotations
import argparse
import math
from pathlib import Path
from scanner.banners import DEFAULT_BANNER_WORKERS, DEFAULT_MAX_BYTES, DEFAULT_MAX_ENDPOINTS
from scanner.contract import SUPPORTED_REPORT_VERSIONS
from scanner.discovery import DEFAULT_MAX_HOSTS, MAX_DISCOVERY_WORKERS
from scanner.events import MAX_EVENT_BYTES
from scanner.http_probe import DEFAULT_HTTP_PORTS
from scanner.profiles import PROFILES
from scanner.tls import DEFAULT_TLS_PORTS, MAX_TLS_WORKERS
from scanner.dns import MAX_DNS_WORKERS

DEFAULT_PORTS=[21,22,23,25,53,80,110,143,443,445,3389]
DEFAULT_WORKERS=64; DEFAULT_PING_TIMEOUT=1.0; DEFAULT_CONNECT_TIMEOUT=1.0; MAX_PORTS=1024
PROJECT_ROOT=Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT_PATH=PROJECT_ROOT/"results"/"scan.json"

def parse_ports(value: str) -> list[int]:
    if not value.strip(): raise argparse.ArgumentTypeError("ports cannot be empty")
    ports=[]; seen=set()
    for item in value.split(","):
        try: port=int(item.strip())
        except ValueError as exc: raise argparse.ArgumentTypeError(f"invalid port: {item!r}") from exc
        if not 1<=port<=65535: raise argparse.ArgumentTypeError(f"port out of range: {port}")
        if port not in seen: seen.add(port); ports.append(port)
        if len(ports)>MAX_PORTS: raise argparse.ArgumentTypeError(f"no more than {MAX_PORTS} unique ports are allowed")
    return ports
def positive_float(value: str) -> float:
    try: parsed=float(value)
    except ValueError as exc: raise argparse.ArgumentTypeError("must be a number") from exc
    if not math.isfinite(parsed) or parsed<=0: raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed
def positive_integer(value: str) -> int:
    try: parsed=int(value)
    except ValueError as exc: raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed<1: raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed
def worker_count(value: str) -> int:
    parsed=positive_integer(value)
    if parsed>MAX_DISCOVERY_WORKERS: raise argparse.ArgumentTypeError(f"workers must be between 1 and {MAX_DISCOVERY_WORKERS}")
    return parsed
def banner_worker_count(value: str) -> int:
    parsed=positive_integer(value)
    if parsed>32: raise argparse.ArgumentTypeError("banner workers must be between 1 and 32")
    return parsed
def banner_byte_limit(value: str) -> int:
    parsed=positive_integer(value)
    if parsed>65536: raise argparse.ArgumentTypeError("banner bytes must be between 1 and 65536")
    return parsed
def tls_worker_count(value: str) -> int:
    parsed=positive_integer(value)
    if parsed>MAX_TLS_WORKERS: raise argparse.ArgumentTypeError(f"TLS workers must be between 1 and {MAX_TLS_WORKERS}")
    return parsed
def dns_worker_count(value: str) -> int:
    parsed=positive_integer(value)
    if parsed>MAX_DNS_WORKERS: raise argparse.ArgumentTypeError(f"DNS workers must be between 1 and {MAX_DNS_WORKERS}")
    return parsed

def create_parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(prog="SCAN",description="Discover hosts and collect structured TCP port scan data.")
    p.add_argument("target",help="IPv4 or IPv6 address/network in CIDR form")
    p.add_argument("--output",default=str(DEFAULT_OUTPUT_PATH),metavar="PATH|-",help="JSON destination; '-' writes JSON only to stdout")
    p.add_argument("--ports",type=parse_ports,default=DEFAULT_PORTS,metavar="PORTS",help="comma-separated TCP ports")
    p.add_argument("--workers",type=worker_count,default=DEFAULT_WORKERS,help=f"global worker limit (1-{MAX_DISCOVERY_WORKERS})")
    p.add_argument("--ping-timeout",type=positive_float,default=DEFAULT_PING_TIMEOUT,metavar="SECONDS")
    p.add_argument("--connect-timeout",type=positive_float,default=DEFAULT_CONNECT_TIMEOUT,metavar="SECONDS")
    p.add_argument("--max-hosts",type=positive_integer,default=DEFAULT_MAX_HOSTS,metavar="COUNT",help="reject targets with more candidate hosts")
    p.add_argument("--collect-banners",action=argparse.BooleanOptionalAction,default=False)
    p.add_argument("--banner-workers",type=banner_worker_count,default=DEFAULT_BANNER_WORKERS); p.add_argument("--banner-max-endpoints",type=positive_integer,default=DEFAULT_MAX_ENDPOINTS); p.add_argument("--banner-max-bytes",type=banner_byte_limit,default=DEFAULT_MAX_BYTES); p.add_argument("--banner-read-timeout",type=positive_float,default=.5)
    p.add_argument("--schema-version",choices=SUPPORTED_REPORT_VERSIONS,default="1.0"); p.add_argument("--history-dir",type=Path); p.add_argument("--lock-timeout",type=positive_float,default=5.0)
    p.add_argument("--events-output",type=Path); p.add_argument("--max-events",type=positive_integer,default=256); p.add_argument("--events-format",choices=("legacy-json","batch-json","ndjson"),default="legacy-json"); p.add_argument("--max-event-bytes",type=positive_integer,default=MAX_EVENT_BYTES); p.add_argument("--events-privacy",choices=("full","hash-only"),default="full")
    p.add_argument("--discovery",choices=("icmp","icmp-tcp","tcp"),default="icmp"); p.add_argument("--discovery-ports",type=parse_ports,default=[443,80,22]); p.add_argument("--discovery-connect-timeout",type=positive_float,default=.5); p.add_argument("--max-discovery-endpoints",type=positive_integer,default=4096)
    p.add_argument("--collect-tls",action=argparse.BooleanOptionalAction,default=False); p.add_argument("--tls-ports",type=parse_ports,default=list(DEFAULT_TLS_PORTS)); p.add_argument("--tls-workers",type=tls_worker_count,default=4); p.add_argument("--tls-max-endpoints",type=positive_integer,default=32); p.add_argument("--tls-connect-timeout",type=positive_float,default=.5); p.add_argument("--tls-handshake-timeout",type=positive_float,default=1.0)
    p.add_argument("--resolve-names",action=argparse.BooleanOptionalAction,default=False); p.add_argument("--dns-workers",type=dns_worker_count,default=4); p.add_argument("--dns-timeout",type=positive_float,default=1.0); p.add_argument("--dns-max-assets",type=positive_integer,default=256)
    p.add_argument("--profile",choices=tuple(PROFILES)); p.add_argument("--collect-neighbors",action=argparse.BooleanOptionalAction,default=False); p.add_argument("--neighbor-privacy",choices=("hash-only","full"),default="hash-only"); p.add_argument("--neighbor-max-records",type=positive_integer,default=256); p.add_argument("--neighbor-timeout",type=positive_float,default=1.0); p.add_argument("--neighbor-interface")
    p.add_argument("--collect-http",action=argparse.BooleanOptionalAction,default=False); p.add_argument("--http-ports",type=parse_ports,default=list(DEFAULT_HTTP_PORTS)); p.add_argument("--http-workers",type=positive_integer,default=4); p.add_argument("--http-max-endpoints",type=positive_integer,default=32); p.add_argument("--http-connect-timeout",type=positive_float,default=.5); p.add_argument("--http-tls-timeout",type=positive_float,default=1.0); p.add_argument("--http-read-timeout",type=positive_float,default=1.0); p.add_argument("--http-max-header-bytes",type=positive_integer,default=16384); p.add_argument("--http-body-hash-bytes",type=positive_integer,default=4096); p.add_argument("--http-method",choices=("head","head-get"),default="head")
    p.add_argument("--correlate-evidence",action=argparse.BooleanOptionalAction,default=True); p.add_argument("--correlation-max-signals",type=positive_integer,default=4096); p.add_argument("--correlation-max-relations",type=positive_integer,default=256)
    return p
