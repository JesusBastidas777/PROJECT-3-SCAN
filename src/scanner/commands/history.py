"""Bounded read-only history list/show commands."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from collections.abc import Sequence

from scanner.loaders import load_json_document, load_snapshot
from scanner.report import serialize_report

SAFE_ID = re.compile(r"^(?:target_[a-f0-9]{20}|snapshot_[a-f0-9]{24})$")


def history_read_main(argv: Sequence[str]) -> int:
    parser=argparse.ArgumentParser(prog="SCAN history"); sub=parser.add_subparsers(dest="command",required=True)
    show=sub.add_parser("show"); show.add_argument("--history-dir",type=Path,required=True); show.add_argument("--snapshot",required=True); show.add_argument("--target",required=True)
    listing=sub.add_parser("list"); listing.add_argument("--history-dir",type=Path,required=True); listing.add_argument("--target")
    try:
        args=parser.parse_args(argv); root=args.history_dir
        if root.is_symlink(): raise OSError("history root cannot be a symlink")
        if args.command == "show":
            if not SAFE_ID.fullmatch(args.target) or not SAFE_ID.fullmatch(args.snapshot): raise ValueError("invalid history identifier")
            value=load_snapshot(root/args.target/f"{args.snapshot}.json")
        else:
            index=load_json_document(root/"index.json"); targets=index.get("targets",{})
            if args.target:
                if not SAFE_ID.fullmatch(args.target): raise ValueError("invalid target identifier")
                targets={args.target:list(targets.get(args.target,[]))}
            value={"history_query_schema_version":"1.0","targets":{key:list(targets[key]) for key in sorted(targets)}}
        sys.stdout.write(serialize_report(value)); return 0
    except BrokenPipeError: return 0
    except (OSError,ValueError,json.JSONDecodeError,UnicodeError) as exc:
        print(f"SCAN: operational error: {exc}",file=sys.stderr); return 1
