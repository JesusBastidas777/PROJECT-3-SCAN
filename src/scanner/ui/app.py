"""Controller for the optional FOREX SCAN Rich interface."""
from __future__ import annotations

import argparse
from dataclasses import replace
from datetime import datetime, timezone
import os
import time

from scanner.commands.runtime import runtime_service
from scanner.integrations.forex import FOREXSCANWorkflow
from scanner.ui import VIEWS
from scanner.ui.errors import describe_error
from scanner.ui.navigation import normalize_view
from scanner.ui.state import UIState


class SCANApplication:
    def __init__(self, service, *, workflow=None, view="overview", refresh_seconds=15.0, max_rows=20):
        self.service = service
        self.workflow = workflow or FOREXSCANWorkflow(service)
        self.view = normalize_view(view)
        if refresh_seconds <= 0:
            raise ValueError("refresh_seconds must be positive")
        self.refresh_seconds = float(refresh_seconds)
        self.max_rows = max(1, min(int(max_rows), 100))

    def collect(self) -> UIState:
        readiness = self.service.check()
        if not readiness.data.get("ready"):
            raise RuntimeError("SCAN runtime is unavailable")
        status = self.service.status().data
        current = status.get("status", status)
        response = self.workflow.view(self.view, limit=self.max_rows)
        renderer = __import__(f"scanner.ui.screens.{self.view}", fromlist=["render"])
        payload = renderer.render(response.data, max_rows=self.max_rows)
        return UIState(
            view=self.view, payload=payload, status=str(current.get("lifecycle", "idle")),
            updated_at=str(current.get("timestamp") or datetime.now(timezone.utc).isoformat()),
        )

    def plan(self, request):
        return self.workflow.plan(request)

    def start(self, request):
        return self.workflow.start(request)

    def cancel(self, scan_id):
        return self.workflow.cancel(scan_id)

    def resume(self, checkpoint_id):
        return self.workflow.resume(checkpoint_id)

    def select_baseline(self, snapshot_id):
        return self.workflow.select_baseline(snapshot_id)

    def export(self, scan_id, destination, *, overwrite=False):
        return self.workflow.export(scan_id, destination, overwrite=overwrite)

    def retry_failed_publication(self, scan_id):
        return self.workflow.retry_failed_publication(scan_id)

    def refresh(self, previous: UIState | None = None, *, include_detail: bool = False) -> UIState:
        try:
            return self.collect()
        except Exception as error:
            description = describe_error(error, include_detail=include_detail)
            if previous is not None:
                return replace(previous, status="degraded", stale=True, error=description["message"], metadata={**previous.metadata, "error": description})
            return UIState(view=self.view, status="degraded", stale=True, error=description["message"], metadata={"error": description})

    def render(self, state: UIState):
        from scanner.ui.rendering import build_shell
        return build_shell(state, max_rows=self.max_rows)

    def run(self, *, once=False, console=None) -> int:
        from rich.console import Console
        console = console or Console(no_color="NO_COLOR" in os.environ, highlight=False, markup=False)
        state = None
        while True:
            state = self.refresh(state)
            console.print(self.render(state))
            if once:
                return 0
            time.sleep(self.refresh_seconds)


def ui_main(argv) -> int:
    parser = argparse.ArgumentParser(prog="SCAN ui")
    parser.add_argument("--view", choices=VIEWS, default="overview")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--refresh", type=float, default=15.0)
    parser.add_argument("--max-rows", type=int, default=20)
    args = parser.parse_args(argv)
    try:
        return SCANApplication(runtime_service(), view=args.view, refresh_seconds=args.refresh, max_rows=args.max_rows).run(once=args.once)
    except KeyboardInterrupt:
        return 0
