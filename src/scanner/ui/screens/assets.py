from scanner.ui.screens import table


def render(data, *, max_rows=20):
    rows = []
    for item in data.get("assets", []):
        rows.append((item.get("asset_id"), item.get("address"), item.get("ip_version"), len(item.get("evidence_refs", [])), item.get("identity_basis", "scoped_address"), "false"))
    return table("ASSETS · PHYSICAL DEVICE NOT ASSERTED", ("ASSET", "ADDRESS", "IP", "EVIDENCE", "IDENTITY BASIS", "PHYSICAL DEVICE"), rows, max_rows=max_rows)
