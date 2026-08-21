from scanner.ui.screens import table


def render(data, *, max_rows=20):
    value = data.get("comparison") or {}
    rows = [("baseline", value.get("baseline_snapshot_id")), ("comparability", value.get("comparability")), ("determined", len(value.get("changes", []))), ("indeterminate", len(value.get("indeterminate", []))), ("limitations", value.get("limitations", []))]
    return table("BASELINE CHANGES · ABSENCE IS NOT OFFLINE", ("FIELD", "VALUE"), rows, max_rows=max_rows)
