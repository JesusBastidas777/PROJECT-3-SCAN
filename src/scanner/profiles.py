"""Versioned deterministic scan-profile expansion."""
from __future__ import annotations
import argparse
from collections.abc import Sequence
from typing import Any

PROFILE_VERSION = "1.0"
PROFILES: dict[str, dict[str, Any]] = {
    "minimal": {"ports": [22, 80, 443], "workers": 32, "discovery": "icmp", "collect_banners": False, "collect_tls": False, "resolve_names": False},
    "standard": {"ports": [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389], "workers": 64, "discovery": "icmp", "collect_banners": False, "collect_tls": False, "resolve_names": False},
    "evidence": {"ports": [22, 80, 443, 445, 3389], "workers": 48, "discovery": "icmp-tcp", "collect_banners": True, "collect_tls": True, "resolve_names": True, "banner_max_endpoints": 32, "tls_max_endpoints": 16, "dns_max_assets": 128},
}
OPTION_DESTINATIONS = {"--ports": "ports", "--workers": "workers", "--discovery": "discovery", "--collect-banners": "collect_banners", "--no-collect-banners": "collect_banners", "--collect-tls": "collect_tls", "--no-collect-tls": "collect_tls", "--resolve-names": "resolve_names", "--no-resolve-names": "resolve_names", "--banner-max-endpoints": "banner_max_endpoints", "--tls-max-endpoints": "tls_max_endpoints", "--dns-max-assets": "dns_max_assets", "--collect-neighbors": "collect_neighbors", "--no-collect-neighbors": "collect_neighbors", "--neighbor-max-records": "neighbor_max_records"}

def apply_profile(args: argparse.Namespace, argv: Sequence[str]) -> argparse.Namespace:
    name = getattr(args, "profile", None); args.profile_version = PROFILE_VERSION if name else None; args.profile_overrides = []
    if not name: return args
    explicit = {destination for token in argv for option, destination in OPTION_DESTINATIONS.items() if token == option or token.startswith(option + "=")}
    for destination, value in PROFILES[name].items():
        if destination not in explicit: setattr(args, destination, list(value) if isinstance(value, list) else value)
    args.profile_overrides = sorted(explicit & PROFILES[name].keys())
    return args
