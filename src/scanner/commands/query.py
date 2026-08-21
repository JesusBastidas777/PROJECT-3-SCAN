"""Read-only evidence query command."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from collections.abc import Sequence

from scanner.contract import canonical_json
from scanner.loaders import DEFAULT_MAX_INPUT_BYTES, load_report_or_snapshot
from scanner.query import query_report
from scanner.report import serialize_report


def _render(value: dict, format_name: str) -> str:
    if format_name == "json": return serialize_report(value)
    if format_name == "ndjson":
        results = value["results"] if isinstance(value["results"], list) else [value["results"]]
        return "".join(canonical_json(item) + "\n" for item in results)
    return f"query={value['query']} count={value['count']} truncated={str(value['truncated']).lower()}\n" + "\n".join(canonical_json(item) for item in (value["results"] if isinstance(value["results"], list) else [value["results"]])) + "\n"


def query_main(argv: Sequence[str]) -> int:
    parser=argparse.ArgumentParser(prog="SCAN query")
    parser.add_argument("report",type=Path); group=parser.add_mutually_exclusive_group()
    group.add_argument("--asset"); group.add_argument("--open-endpoints",action="store_true"); group.add_argument("--errors",action="store_true"); group.add_argument("--coverage",action="store_true"); group.add_argument("--evidence-ref")
    parser.add_argument("--output",choices=("json","ndjson","text"),default="json"); parser.add_argument("--max-input-bytes",type=int,default=DEFAULT_MAX_INPUT_BYTES); parser.add_argument("--max-results",type=int,default=10000)
    try:
        args=parser.parse_args(argv); report,_=load_report_or_snapshot(args.report,max_bytes=args.max_input_bytes)
        value=query_report(report,asset_id=args.asset,open_endpoints=args.open_endpoints,errors=args.errors,coverage=args.coverage,evidence_ref=args.evidence_ref,max_results=args.max_results)
        sys.stdout.write(_render(value,args.output)); return 0
    except BrokenPipeError: return 0
    except (OSError,ValueError,json.JSONDecodeError,UnicodeError) as exc:
        print(f"SCAN: operational error: {exc}",file=sys.stderr); return 1
