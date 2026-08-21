"""Safe, cwd-independent runtime paths for SCAN."""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path


SOURCE_ROOT = Path(__file__).resolve().parents[2]


def default_runtime_dir(environ: dict[str, str] | None = None) -> Path:
    env = os.environ if environ is None else environ
    explicit = env.get("SCAN_RUNTIME_DIR")
    if explicit:
        return Path(explicit).expanduser()
    if os.name == "nt" and env.get("LOCALAPPDATA"):
        return Path(env["LOCALAPPDATA"]) / "SCAN" / "runtime"
    state = env.get("XDG_STATE_HOME")
    base = Path(state) if state else Path.home() / ".local" / "state"
    return base / "scan" / "runtime"


@dataclass(frozen=True)
class SCANRuntimeConfig:
    root: Path
    heartbeat_max_age_seconds: float = 15.0
    history_max_entries: int = 256
    history_max_bytes: int = 16 * 1024 * 1024
    public_max_bytes: int = 4 * 1024 * 1024
    auto_enqueue: bool = False

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> "SCANRuntimeConfig":
        return cls(default_runtime_dir(environ))

    @property
    def public_dir(self) -> Path:
        return self.root / "public"

    @property
    def private_dir(self) -> Path:
        return self.root / "private"

    @property
    def outbox_dir(self) -> Path:
        return self.root / "outbox"

    @property
    def readiness_path(self) -> Path:
        return self.public_dir / "readiness.json"

    @property
    def heartbeat_path(self) -> Path:
        return self.public_dir / "heartbeat.json"

    @property
    def status_path(self) -> Path:
        return self.public_dir / "status.json"

    @property
    def latest_scan_path(self) -> Path:
        return self.public_dir / "latest_scan.json"

    @property
    def public_history_path(self) -> Path:
        return self.public_dir / "history.jsonl"

    @property
    def reports_dir(self) -> Path:
        return self.private_dir / "reports"

    @property
    def snapshots_dir(self) -> Path:
        return self.private_dir / "snapshots"

    @property
    def checkpoints_dir(self) -> Path:
        return self.private_dir / "checkpoints"

    @property
    def locks_dir(self) -> Path:
        return self.private_dir / "locks"

    def required_directories(self) -> tuple[Path, ...]:
        states = tuple(self.outbox_dir / state for state in (
            "pending", "processing", "acknowledged", "failed",
        ))
        return (
            self.root, self.public_dir, self.private_dir, self.outbox_dir,
            self.reports_dir, self.snapshots_dir, self.checkpoints_dir,
            self.locks_dir, *states,
        )


def validate_runtime_root(root: Path, *, source_root: Path = SOURCE_ROOT) -> None:
    if not root.is_absolute():
        raise ValueError("SCAN_RUNTIME_DIR must be absolute")
    if root.is_symlink():
        raise OSError("runtime root cannot be a symlink")
    resolved = root.resolve()
    try:
        resolved.relative_to(source_root.resolve())
    except ValueError:
        pass
    else:
        raise ValueError("runtime root must be outside the source tree")


def prepare_runtime(config: SCANRuntimeConfig) -> None:
    validate_runtime_root(config.root)
    for path in config.required_directories():
        if path.exists() and path.is_symlink():
            raise OSError(f"runtime directory cannot be a symlink: {path}")
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != "nt":
        try:
            config.root.chmod(0o700)
        except OSError:
            pass
