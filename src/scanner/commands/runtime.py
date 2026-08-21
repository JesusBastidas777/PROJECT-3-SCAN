"""Stable runtime lifecycle CLI backed by SCANService objects."""
from __future__ import annotations

import argparse
from collections.abc import Sequence
import sys

from scanner import SCANConfig, SCANError, SCANService
from scanner.models import SCANResponseV1
from scanner.runtime import SCANRuntime
from scanner.runtime_paths import SCANRuntimeConfig


EXIT_OK = 0
EXIT_DEGRADED = 1
EXIT_UNAVAILABLE = 2
EXIT_CONTRACT = 3
EXIT_USAGE = 64


def runtime_service() -> SCANService:
    config = SCANRuntimeConfig.from_env()
    return SCANService(SCANConfig(config.reports_dir, config.snapshots_dir, config.outbox_dir, config))


def emit(response: SCANResponseV1) -> int:
    sys.stdout.write(response.to_json() + "\n")
    return EXIT_OK if response.status == "success" else EXIT_DEGRADED


def runtime_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="SCAN runtime")
    parser.add_argument("action", choices=("start", "stop"))
    args = parser.parse_args(argv)
    service = runtime_service()
    try:
        runtime = service.runtime or SCANRuntime(service.config.runtime)
        if args.action == "start":
            runtime.start()
        else:
            runtime.stop()
        return emit(SCANResponseV1(data={"runtime": args.action, "status": runtime.lifecycle}))
    except (OSError, ValueError, RuntimeError, SCANError) as exc:
        print(f"SCAN: runtime error: {exc}", file=sys.stderr)
        return EXIT_UNAVAILABLE
