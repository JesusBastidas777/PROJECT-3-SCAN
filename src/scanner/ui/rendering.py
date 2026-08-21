"""Pure bounded Rich renderer for a pre-collected SCAN UI state."""
from __future__ import annotations

from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from scanner.ui import VIEWS
from scanner.ui.theme import CRITICAL, INFO, MUTED, SECONDARY, TITLE, status_style


def build_shell(state, *, max_rows: int = 20):
    max_rows = max(1, min(int(max_rows), 100))
    navigation = Table.grid(expand=True)
    for _ in VIEWS:
        navigation.add_column()
    navigation.add_row(*[Text(name.upper(), style=INFO if name == state.view else MUTED) for name in VIEWS])
    if state.payload is None:
        message = state.error or f"{state.view.title()} has no available data"
        body = Panel(Text(message, style=CRITICAL if state.error else SECONDARY), title=state.view.upper(), border_style=TITLE)
    elif isinstance(state.payload, dict):
        rows = list(state.payload.items())[:max_rows] if isinstance(state.payload, dict) else [("VALUE", state.payload)]
        table = Table.grid(padding=(0, 2))
        table.add_column(style=TITLE); table.add_column(style=INFO)
        for name, value in rows:
            table.add_row(str(name).upper(), str(value))
        body = Panel(table, title=state.view.upper(), border_style=TITLE)
    else:
        body = Panel(state.payload, title=state.view.upper(), border_style=TITLE)
    footer = Text(
        f"Status {state.status.upper()} | Last update {state.updated_at or 'unknown'}" + (" | STALE" if state.stale else ""),
        style=status_style("stale" if state.stale else state.status),
    )
    return Panel(Group(navigation, body, footer), title="FOREX SCAN", border_style=TITLE)
