"""Pure Rich screens for FOREX SCAN."""
from __future__ import annotations

from rich.table import Table
from rich.text import Text
from scanner.ui.theme import INFO, MUTED, TITLE


def table(title: str, columns: tuple[str, ...], rows, *, max_rows: int = 20):
    value = Table(title=title, title_style=TITLE, border_style=TITLE)
    for column in columns:
        value.add_column(column, style=TITLE if column == columns[0] else INFO)
    selected = list(rows)[:max(1, min(max_rows, 100))]
    if not selected:
        value.add_row(*(["No observations"] + [""] * (len(columns) - 1)), style=MUTED)
    for row in selected:
        value.add_row(*(str(item) for item in row))
    return value
