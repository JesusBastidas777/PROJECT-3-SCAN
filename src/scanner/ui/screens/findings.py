from scanner.ui.screens import table


def render(data, *, max_rows=20):
    rows = ((item.get("statement"), item.get("confidence"), item.get("evidence_refs"), item.get("limitations", [])) for item in data.get("findings", []))
    return table("FACTUAL FINDINGS", ("FINDING", "CONFIDENCE", "EVIDENCE", "LIMITATIONS"), rows, max_rows=max_rows)
