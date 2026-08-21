# FOREX SCAN release-candidate contract

The normative boundary is the Python validators registered in
`scanner.contract_registry`; JSON Schemas are portable structural descriptions
and parity-tested for required fields and versions.

FOREX uses only `SCANConfig`, `SCANService`, `FOREXSCANWorkflow` or validated
documents below `runtime/public`. It never reads `runtime/private`.

Publication validates Report 2.2, writes immutable report/feed/manifest data,
atomically replaces `latest_scan.json`, appends bounded NDJSON history, optionally
enqueues an idempotent hash-only feed, then publishes status and heartbeat. A
matching heartbeat `last_publish_sequence` confirms visibility. ACK means delivery,
not evidence truth or security acceptance.

SCAN is an evidence sensor. FOREX owns interpretation, correlation, scoring and
decisions. Absence, timeout, hints, PTR, TLS and neighbor evidence retain their
existing conservative meanings.
