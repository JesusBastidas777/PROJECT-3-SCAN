"""Read-only SCAN readiness/heartbeat commands."""
from __future__ import annotations

import argparse
from collections.abc import Sequence
import sys

from scanner.commands.runtime import EXIT_CONTRACT, emit, runtime_service


def health_main(argv: Sequence[str], *, check: bool = False) -> int:
    parser = argparse.ArgumentParser(prog="SCAN check" if check else "SCAN health")
    parser.add_argument("--json", action="store_true")
    parser.parse_args(argv)
    try:
        service = runtime_service()
        return emit(service.check() if check else service.health())
    except (OSError, ValueError) as exc:
        print(f"SCAN: invalid runtime contract: {exc}", file=sys.stderr); return EXIT_CONTRACT
