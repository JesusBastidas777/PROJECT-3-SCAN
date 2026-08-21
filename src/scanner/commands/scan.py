"""SCAN acquisition command and exit-code boundary."""
from __future__ import annotations
import json
import sys
from collections.abc import Callable, Sequence
from typing import Any
from scanner.configuration import ScanRequest, resolve_request
from scanner.discovery import TargetValidationError
from scanner.outputs import write_scan_outputs
from scanner.profiles import apply_profile
from scanner.scan_parser import create_parser
from scanner.scan_pipeline import execute_scan

EXIT_SUCCESS=0; EXIT_OPERATIONAL_ERROR=1; EXIT_USAGE=2; EXIT_INTERRUPTED=130

def collect_report(args: Any) -> dict[str,Any]:
    # Complete legacy hand-built Namespaces with the canonical parser defaults.
    defaults=create_parser().parse_args([str(args.target)])
    for key,value in vars(args).items(): setattr(defaults,key,value)
    return execute_scan(resolve_request(ScanRequest.from_namespace(defaults)))

def scan_main(argv: Sequence[str], *, collector: Callable[[Any],dict[str,Any]]=collect_report, output_writer: Callable[[dict[str,Any],Any],None]=write_scan_outputs) -> int:
    parser=create_parser(); arguments=list(argv); args=apply_profile(parser.parse_args(arguments),arguments)
    try:
        report=collector(args)
        if getattr(args,"checkpoint_dir",None) is not None and report.get("schema_version")=="2.2":
            from scanner.checkpoints import build_checkpoint,save_checkpoint,stable_work_unit_id
            completed=[{"work_unit_id":stable_work_unit_id({"observation_id":item["observation_id"]}),"observation_id":item["observation_id"]} for item in report.get("observations",[])]
            checkpoint=build_checkpoint(target=report["target"],measurement_scope_fingerprint=report["measurement_scope_fingerprint"],execution_policy_fingerprint=report["execution_policy_fingerprint"],configuration=report["effective_configuration"],completed=completed,pending=[],evidence=report.get("observations",[]),privacy=args.events_privacy)
            checkpoint["acquisition"]=report.get("acquisition",{}); save_checkpoint(checkpoint,args.checkpoint_dir,lock_timeout=args.lock_timeout)
        output_writer(report,args)
    except TargetValidationError as exc: print(f"SCAN: invalid target: {exc}",file=sys.stderr); return EXIT_USAGE
    except KeyboardInterrupt: print("SCAN: interrupted",file=sys.stderr); return EXIT_INTERRUPTED
    except BrokenPipeError: return EXIT_SUCCESS
    except (OSError,ValueError) as exc: print(f"SCAN: operational error: {exc}",file=sys.stderr); return EXIT_OPERATIONAL_ERROR
    except Exception as exc: print(f"SCAN: unexpected failure: {exc}",file=sys.stderr); return EXIT_OPERATIONAL_ERROR
    return EXIT_SUCCESS
