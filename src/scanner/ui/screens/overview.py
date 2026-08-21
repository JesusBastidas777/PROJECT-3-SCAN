from scanner.ui.screens import table


def render(data, *, max_rows=20):
    value = data.get("overview") or {}
    fields = ("runtime_state", "job_state", "target", "scan_id", "duration_ms", "partial", "resumed", "counts", "coverage_summary", "references", "outbox_state")
    return table("OPERATIONAL OVERVIEW", ("FIELD", "VALUE"), ((name, value.get(name)) for name in fields), max_rows=max_rows)
