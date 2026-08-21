from scanner.ui.screens import table


def render(data, *, max_rows=20):
    rows = ((name, value) for name, value in data.items())
    return table("RUNTIME · READINESS HEARTBEAT PUBLICATION", ("COMPONENT", "STATE"), rows, max_rows=max_rows)
