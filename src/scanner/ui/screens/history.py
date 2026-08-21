from scanner.ui.screens import table


def render(data, *, max_rows=20):
    rows = ((item.get("scan_id"), item.get("completed_at"), item.get("target"), item.get("duration_ms"), item.get("partial"), item.get("resumed"), item.get("baseline_eligible")) for item in data.get("scans", []))
    return table("BOUNDED SCAN HISTORY", ("SCAN", "TIME", "TARGET", "DURATION", "PARTIAL", "RESUMED", "BASELINE"), rows, max_rows=max_rows)
