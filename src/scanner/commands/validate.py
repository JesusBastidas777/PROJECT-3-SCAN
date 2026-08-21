"""Read-only offline validation CLI."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys
from collections.abc import Sequence
from scanner.report import serialize_report
from scanner.validation import validate_file
def validate_main(argv: Sequence[str]) -> int:
    p=argparse.ArgumentParser(prog="SCAN validate"); p.add_argument("file",type=Path); p.add_argument("--type"); p.add_argument("--version"); p.add_argument("--format",choices=("text","json"),default="text"); p.add_argument("--strict",action="store_true"); p.add_argument("--max-input-bytes",type=int,default=16*1024*1024); a=p.parse_args(argv)
    result=validate_file(a.file,type_name=a.type,version=a.version,max_bytes=a.max_input_bytes,strict=a.strict)
    if a.format=="json": sys.stdout.write(serialize_report(result))
    else: sys.stdout.write(("valid" if result["valid"] else "invalid")+" contract="+str(result["detected"])+"\n")
    return 0 if result["valid"] else 1
