from scanner.ui.screens import table


def render(data, *, max_rows=20):
    rows = []
    for item in data.get("endpoints", []):
        hint = item.get("service_hint", {}).get("name") if isinstance(item.get("service_hint"), dict) else item.get("service_hint")
        rows.append((item.get("asset_id"), item.get("transport", "tcp"), item.get("port"), item.get("state"), f"HINT: {hint}" if hint else "HINT: none", item.get("observation_id")))
    return table("ENDPOINT OBSERVATIONS", ("ASSET", "TRANSPORT", "PORT", "STATE", "SERVICE HINT", "EVIDENCE"), rows, max_rows=max_rows)
