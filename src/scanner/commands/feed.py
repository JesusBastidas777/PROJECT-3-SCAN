"""Offline compact FOREX feed command."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from collections.abc import Sequence

from scanner.feed import build_feed
from scanner.feed_io import write_feed
from scanner.loaders import load_report_or_snapshot


def feed_main(argv: Sequence[str]) -> int:
    parser=argparse.ArgumentParser(prog="SCAN feed"); parser.add_argument("report",type=Path); parser.add_argument("--output",default="-"); parser.add_argument("--feed-format",choices=("json","ndjson"),default="json"); parser.add_argument("--feed-max-assets",type=int,default=1024); parser.add_argument("--feed-max-endpoints",type=int,default=4096); parser.add_argument("--feed-max-bytes",type=int,default=4*1024*1024); parser.add_argument("--feed-privacy",choices=("hash-only","full"),default="hash-only")
    try:
        args=parser.parse_args(argv); report,snapshot=load_report_or_snapshot(args.report)
        value=build_feed(report,snapshot=snapshot,privacy=args.feed_privacy,max_assets=args.feed_max_assets,max_endpoints=args.feed_max_endpoints,max_bytes=args.feed_max_bytes)
        write_feed(value,args.output,format_name=args.feed_format); return 0
    except BrokenPipeError: return 0
    except (OSError,ValueError,json.JSONDecodeError,UnicodeError) as exc:
        print(f"SCAN: operational error: {exc}",file=sys.stderr); return 1
