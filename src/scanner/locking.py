"""Portable exclusive lockfile protocol with finite waiting."""
from __future__ import annotations
import json
import os
from pathlib import Path
import time

class FileLock:
    def __init__(self, path: Path, *, timeout: float = 5.0, stale_after: float = 300.0):
        if timeout <= 0 or stale_after <= 0: raise ValueError("lock timeouts must be positive")
        self.path, self.timeout, self.stale_after, self.acquired = Path(path), timeout, stale_after, False
    def __enter__(self) -> "FileLock":
        deadline = time.monotonic() + self.timeout
        payload = json.dumps({"pid": os.getpid(), "created_unix": time.time()}).encode("ascii")
        while True:
            try:
                descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                try: os.write(descriptor, payload); os.fsync(descriptor)
                finally: os.close(descriptor)
                self.acquired = True
                return self
            except FileExistsError:
                try:
                    if time.time() - self.path.stat().st_mtime > self.stale_after and not self.path.is_symlink():
                        self.path.unlink(); continue
                except FileNotFoundError: continue
                if time.monotonic() >= deadline: raise TimeoutError(f"timed out waiting for history lock: {self.path.name}")
                time.sleep(min(.05, max(0, deadline - time.monotonic())))
    def __exit__(self, *_: object) -> None:
        if self.acquired: self.path.unlink(missing_ok=True); self.acquired = False
