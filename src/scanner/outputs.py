"""Report, history and FOREX output coordination."""
from pathlib import Path
import sys
from typing import Any
from scanner.event_io import write_events
from scanner.events import events_from_report
from scanner.report import serialize_report, write_report_atomic
from scanner.snapshots import save_snapshot

def write_scan_outputs(report: dict[str,Any], args: Any) -> None:
    if args.history_dir is not None:
        if args.schema_version not in {"2.0","2.1"}: raise ValueError("--history-dir requires --schema-version 2.0 or 2.1")
        _,path=save_snapshot(report,args.history_dir,lock_timeout=args.lock_timeout); print(f"SCAN: snapshot written to {path}",file=sys.stderr)
    if args.events_output is not None:
        if args.schema_version not in {"2.0","2.1"}: raise ValueError("--events-output requires --schema-version 2.0 or 2.1")
        if str(args.events_output)=="-" and args.output=="-": raise ValueError("report and events cannot both use stdout")
        write_events(events_from_report(report,max_events=args.max_events),args.events_output,format_name=args.events_format,max_event_bytes=args.max_event_bytes,privacy=args.events_privacy); print(f"SCAN: events written to {args.events_output}",file=sys.stderr)
    if args.output=="-": sys.stdout.write(serialize_report(report))
    else:
        path=Path(args.output).expanduser(); write_report_atomic(report,path); print(f"SCAN: report written to {path}",file=sys.stderr)
