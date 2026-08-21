"""Single semantic color source for the FOREX SCAN UI."""

TITLE = "#808000"  # Rich-compatible DarkYellow equivalent.
INFO = "yellow"
SECONDARY = "grey62"
MUTED = "bright_black"
CRITICAL = "red"
HEALTHY = "green"
UNKNOWN = "grey50"


def status_style(value) -> str:
    normalized = str(value or "unknown").lower()
    if normalized in {"healthy", "success", "ready", "idle", "completed"}:
        return HEALTHY
    if normalized in {"critical", "failed", "crashed", "degraded"}:
        return CRITICAL
    if normalized in {"unknown", "unavailable", "stale", "stopped"}:
        return UNKNOWN
    return INFO
