"""Top-level command dispatch without acquisition responsibilities."""
from __future__ import annotations
from collections.abc import Callable, Sequence
from scanner.commands.compare import compare_main
from scanner.commands.feed import feed_main
from scanner.commands.history import history_read_main
from scanner.commands.query import query_main
from scanner.commands.scan import scan_main
from scanner.commands.plan import plan_main
from scanner.commands.validate import validate_main
from scanner.commands.migrate import migrate_main
from scanner.commands.outbox import outbox_main
from scanner.commands.capabilities import capabilities_main
from scanner.commands.health import health_main
from scanner.commands.runtime import emit, runtime_main, runtime_service
from scanner.commands.status import status_main
from scanner.configuration import ScanRequest
from scanner.errors import SCANError
from scanner.scan_parser import create_parser

def dispatch(argv: Sequence[str], *, scan_runner: Callable[[Sequence[str]],int]=scan_main, history_retain_runner: Callable[[Sequence[str]],int]|None=None) -> int:
    args=list(argv)
    if args[:1]==["check"]: return health_main(args[1:],check=True)
    if args[:1]==["status"]: return status_main(args[1:])
    if args[:1]==["health"]: return health_main(args[1:])
    if args[:1]==["capabilities"]: return capabilities_main(args[1:])
    if args[:1]==["runtime"]: return runtime_main(args[1:])
    if args[:1]==["latest"]: return status_main(args[1:],latest=True)
    if args[:1]==["contract-version"]:
        import sys
        sys.stdout.write("SCAN public 1.0; report 2.2\n"); return 0
    if args[:1]==["run"]:
        try:
            parser=create_parser(); parsed=parser.parse_args(args[1:])
            parsed.schema_version="2.2"
            service=runtime_service()
            if service.runtime is not None: service.runtime.start()
            return emit(service.start_scan(ScanRequest.from_namespace(parsed)))
        except SCANError as exc:
            import sys
            print(f"SCAN: {exc.code}: {exc}",file=sys.stderr); return 1
    if args[:1]==["cancel"]:
        if len(args)!=2: return 64
        try: return emit(runtime_service().cancel_scan(args[1]))
        except SCANError as exc:
            import sys
            print(f"SCAN: {exc.code}: {exc}",file=sys.stderr); return 2
    if args[:1]==["plan"]: return plan_main(args[1:])
    if args[:1]==["validate"]: return validate_main(args[1:])
    if args[:1]==["migrate"]: return migrate_main(args[1:])
    if args[:1]==["outbox"]: return outbox_main(args[1:])
    if args[:1]==["compare"]: return compare_main(args[1:])
    if args[:1]==["query"]: return query_main(args[1:])
    if args[:1]==["feed"]: return feed_main(args[1:])
    if args[:2]==["history","retain"] and history_retain_runner: return history_retain_runner(args[2:])
    if args[:1]==["history"]: return history_read_main(args[1:])
    if args[:1]==["scan"]: args=args[1:]
    return scan_runner(args)
