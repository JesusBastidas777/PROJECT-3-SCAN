"""Job-oriented local SCAN runtime with one active scan."""
from __future__ import annotations

import threading
import uuid

from scanner.errors import ScanAlreadyRunning
from scanner.job_state import JobState, TERMINAL_JOB_STATES
from scanner.readiness import publish_readiness
from scanner.runtime_health import RuntimeHealth
from scanner.runtime_paths import SCANRuntimeConfig, prepare_runtime
from scanner.locking import FileLock


class SCANRuntime:
    def __init__(self, config: SCANRuntimeConfig, *, runtime_instance_id: str | None = None, health: RuntimeHealth | None = None):
        self.config = config
        self.runtime_instance_id = runtime_instance_id or str(uuid.uuid4())
        self.health = health or RuntimeHealth(config, self.runtime_instance_id)
        self.lifecycle = "starting"
        self.active_job: JobState | None = None
        self.last_successful_scan_id: str | None = None
        self._guard = threading.Lock()
        self._job_file_lock = None

    def start(self) -> None:
        prepare_runtime(self.config)
        readiness = publish_readiness(self.config)
        if not readiness["ready"]:
            raise RuntimeError("SCAN runtime readiness failed")
        self.health.publish(lifecycle="starting")
        self.lifecycle = "idle"
        self.health.publish(lifecycle="idle")

    def begin_job(self, scan_id: str, target: str) -> JobState:
        with self._guard:
            if self.active_job is not None and self.active_job.state not in TERMINAL_JOB_STATES:
                raise ScanAlreadyRunning("a SCAN job is already active", {"scan_id": self.active_job.scan_id})
            lock = FileLock(self.config.locks_dir / "active-scan.lock", timeout=.1, stale_after=86400)
            try: lock.__enter__()
            except TimeoutError as exc: raise ScanAlreadyRunning("another SCAN runtime owns the active job lock") from exc
            self._job_file_lock = lock
            self.active_job = JobState(scan_id=scan_id, target=target)
            self.health.publish(lifecycle=self.lifecycle, job=self.active_job, last_successful_scan_id=self.last_successful_scan_id)
            return self.active_job

    def transition_job(self, state: str) -> JobState:
        if self.active_job is None:
            raise ValueError("no active SCAN job")
        self.active_job.transition(state)
        if state == "completed":
            self.last_successful_scan_id = self.active_job.scan_id
        self.health.publish(lifecycle=self.lifecycle, job=self.active_job, last_successful_scan_id=self.last_successful_scan_id)
        if state in TERMINAL_JOB_STATES and self._job_file_lock is not None:
            self._job_file_lock.__exit__(None, None, None); self._job_file_lock = None
        return self.active_job

    def stop(self) -> None:
        if self.active_job is not None and self.active_job.state not in TERMINAL_JOB_STATES:
            raise RuntimeError("cannot stop while a SCAN job is active")
        self.lifecycle = "stopped"
        self.health.publish(lifecycle="stopped", job=self.active_job, last_successful_scan_id=self.last_successful_scan_id)

    def mark_crashed(self, error: str) -> None:
        self.lifecycle = "crashed"
        if self.active_job is not None:
            self.active_job.errors.append({"code": "runtime_crash", "message": error})
        self.health.publish(lifecycle="crashed", job=self.active_job, last_successful_scan_id=self.last_successful_scan_id)
