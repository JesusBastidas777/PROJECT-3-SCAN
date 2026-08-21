"""Top-level command dispatch without acquisition responsibilities."""
from __future__ import annotations
from collections.abc import Callable, Sequence
from scanner.commands.compare import compare_main
from scanner.commands.feed import feed_main
from scanner.commands.history import history_read_main
from scanner.commands.query import query_main
from scanner.commands.scan import scan_main

def dispatch(argv: Sequence[str], *, scan_runner: Callable[[Sequence[str]],int]=scan_main, history_retain_runner: Callable[[Sequence[str]],int]|None=None) -> int:
    args=list(argv)
    if args[:1]==["compare"]: return compare_main(args[1:])
    if args[:1]==["query"]: return query_main(args[1:])
    if args[:1]==["feed"]: return feed_main(args[1:])
    if args[:2]==["history","retain"] and history_retain_runner: return history_retain_runner(args[2:])
    if args[:1]==["history"]: return history_read_main(args[1:])
    if args[:1]==["scan"]: args=args[1:]
    return scan_runner(args)
