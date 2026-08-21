"""Read-only SCAN capability command."""
from __future__ import annotations

import argparse
from collections.abc import Sequence

from scanner.commands.runtime import emit, runtime_service


def capabilities_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="SCAN capabilities")
    parser.add_argument("--json", action="store_true")
    parser.parse_args(argv)
    return emit(runtime_service().capabilities())
