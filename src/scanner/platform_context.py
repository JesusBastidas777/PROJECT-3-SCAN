"""Stable runtime network-context classification."""

from __future__ import annotations

import platform
from pathlib import Path


def network_context(*, system: str | None = None, release_text: str | None = None) -> str:
    name = (system or platform.system()).lower()
    if name == "windows":
        return "windows_host"
    if name == "linux":
        release = release_text
        if release is None:
            try:
                release = Path("/proc/sys/kernel/osrelease").read_text(encoding="ascii")
            except OSError:
                release = platform.release()
        return "wsl_guest" if "microsoft" in release.lower() else "linux_host"
    return "unsupported_platform"
