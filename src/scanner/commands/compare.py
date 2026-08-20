"""Read-only snapshot comparison command."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
from collections.abc import Sequence
from typing import Any
from scanner.changes import build_comparison
from scanner.report import serialize_report, write_report_atomic

MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024

def read_snapshot(path: Path) -> dict[str, Any]:
    supplied = Path(path)
    if supplied.is_symlink(): raise OSError("snapshot path cannot be a symlink")
    if supplied.stat().st_size > MAX_SNAPSHOT_BYTES: raise OSError("snapshot exceeds size limit")
    value = json.loads(supplied.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("snapshot_id"), str) or value.get("report", {}).get("schema_version") != "2.0":
        raise ValueError("invalid schema-2.0 snapshot")
    return value

def compare_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="SCAN compare")
    parser.add_argument("baseline", type=Path)
    parser.add_argument("current", type=Path)
    parser.add_argument("--output", default="-", metavar="PATH|-")
    try:
        args = parser.parse_args(argv)
        result = build_comparison(read_snapshot(args.baseline), read_snapshot(args.current))
        if args.output == "-": sys.stdout.write(serialize_report(result))
        else: write_report_atomic(result, Path(args.output))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"SCAN: operational error: {exc}", file=sys.stderr); return 1
