"""Zero-acquisition deterministic scan plan command."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys
from collections.abc import Sequence
from scanner.configuration import ScanRequest, resolve_request
from scanner.discovery import TargetValidationError
from scanner.planner import build_scan_plan
from scanner.profiles import apply_profile
from scanner.report import serialize_report, write_report_atomic
from scanner.scan_parser import create_parser

def plan_main(argv: Sequence[str]) -> int:
    parser=create_parser(); parser.prog="SCAN plan"; parser.add_argument("--format",choices=("text","json"),default="json")
    arguments=list(argv); args=apply_profile(parser.parse_args(arguments),arguments)
    try:
        plan=build_scan_plan(resolve_request(ScanRequest.from_namespace(args)))
        text=(serialize_report(plan) if args.format=="json" else f"plan={plan['plan_id']} target={plan['target']['network']} candidates={plan['target']['candidate_hosts']} probes=0\n")
        if args.output=="-": sys.stdout.write(text)
        else:
            if args.format=="json": write_report_atomic(plan,Path(args.output))
            else: Path(args.output).write_text(text,encoding="utf-8")
        return 0
    except TargetValidationError as exc: print(f"SCAN: invalid target: {exc}",file=sys.stderr); return 2
    except (OSError,ValueError) as exc: print(f"SCAN: operational error: {exc}",file=sys.stderr); return 1
