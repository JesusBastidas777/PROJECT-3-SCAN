"""Read-only SCAN status and latest commands."""
from __future__ import annotations

import argparse
from collections.abc import Sequence
import sys

from scanner.errors import SCANError
from scanner.commands.runtime import EXIT_CONTRACT, EXIT_UNAVAILABLE, emit, runtime_service


def status_main(argv: Sequence[str], *, latest: bool = False) -> int:
    parser = argparse.ArgumentParser(prog="SCAN latest" if latest else "SCAN status")
    parser.add_argument("--json", action="store_true")
    parser.parse_args(argv)
    try:
        service = runtime_service()
        return emit(service.get_latest_scan() if latest else service.status())
    except SCANError as exc:
        print(f"SCAN: {exc.code}: {exc}", file=sys.stderr); return EXIT_UNAVAILABLE
    except (OSError, ValueError) as exc:
        print(f"SCAN: invalid runtime contract: {exc}", file=sys.stderr); return EXIT_CONTRACT
