"""Compatibility bootstrap for the modular SCAN command line."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
from collections.abc import Sequence

from scanner.cli import dispatch
from scanner.commands.scan import EXIT_INTERRUPTED, EXIT_OPERATIONAL_ERROR, EXIT_SUCCESS, EXIT_USAGE
from scanner.commands.scan import collect_report as _collect_report
from scanner.commands.scan import scan_main
from scanner.outputs import write_scan_outputs
from scanner.retention import retain_snapshots
from scanner.report import serialize_report, write_report_atomic
from scanner.scan_parser import *  # compatibility facade for established imports

def collect_report(args: argparse.Namespace):
    """Compatibility facade for callers that imported ``main.collect_report``."""
    return _collect_report(args)

def _scan_runner(argv: Sequence[str]) -> int:
    return scan_main(argv,collector=collect_report,output_writer=write_scan_outputs)

def history_retain_main(argv: Sequence[str]) -> int:
    parser=argparse.ArgumentParser(prog="SCAN history retain"); parser.add_argument("--history-dir",type=Path,required=True); parser.add_argument("--keep-last",type=positive_integer); parser.add_argument("--max-age-days",type=positive_integer); parser.add_argument("--lock-timeout",type=positive_float,default=5.0); parser.add_argument("--dry-run",action="store_true"); parser.add_argument("--apply",action="store_true")
    args=parser.parse_args(argv)
    if args.apply and args.dry_run: parser.error("--apply and --dry-run are mutually exclusive")
    try:
        value=retain_snapshots(args.history_dir,keep_last=args.keep_last,max_age_days=args.max_age_days,dry_run=not args.apply,lock_timeout=args.lock_timeout); sys.stdout.write(serialize_report(value)); return EXIT_SUCCESS
    except (OSError,ValueError,TimeoutError,json.JSONDecodeError) as exc: print(f"SCAN: operational error: {exc}",file=sys.stderr); return EXIT_OPERATIONAL_ERROR

def main(argv: Sequence[str]|None=None) -> int:
    return dispatch(list(argv) if argv is not None else sys.argv[1:],scan_runner=_scan_runner,history_retain_runner=history_retain_main)

if __name__=="__main__": raise SystemExit(main())
