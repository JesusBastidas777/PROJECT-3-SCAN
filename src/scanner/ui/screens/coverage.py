from scanner.ui.screens import table


def render(data, *, max_rows=20):
    phases = (data.get("coverage") or {}).get("phases", {})
    keys = ("eligible", "selected", "excluded", "scheduled", "started", "completed", "timeout", "error", "cancelled", "not_started")
    rows = ((name, *(phase.get("counts", {}).get(key, 0) for key in keys), (phase.get("termination") or {}).get("reason_code")) for name, phase in sorted(phases.items()))
    return table("MEASUREMENT COVERAGE", ("CAPABILITY", *[key.upper() for key in keys], "TERMINATION"), rows, max_rows=max_rows)
