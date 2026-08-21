# SCAN to FOREX integration

Fifth-stage integration can use Feed 1.1 and local Outbox Item 1.0. FOREX validates, deduplicates and explicitly ACKs delivery. ACK is not semantic acceptance. Partial, excluded, budget-stopped and resumed evidence retain distinct coverage and temporal semantics.

Use `python3 src/main.py TARGET --output -` for frozen schema 1.0, or add
`--schema-version 2.0` for assets, precise observations, service hints,
fingerprints, capabilities and structured errors. Stdout remains one JSON
document; operational messages use stderr.

`--collect-banners` enables bounded passive reads only on endpoints observed
open. Banners are untrusted and potentially sensitive. SCAN does not follow
redirects, authenticate, send credentials, or pretend plain sockets support TLS.

`--history-dir PATH` stores immutable schema-2.0 snapshots. Writes use a finite
portable lock timeout. Retention is a separate explicit command, defaults to
dry-run, and never means that an asset vanished. Comparisons cover
only common measured scope: missing data and unknown/error transitions remain
indeterminate. `--events-output PATH` writes bounded event arrays; validate
`event_schema_version` independently and deduplicate using `deduplication_key`.
Events may instead use a versioned batch or NDJSON. Each event is validated
before local output; delivery is deduplication-friendly, not exactly-once.

- `open` means TCP connect succeeded, not vulnerability.
- `closed` means an explicit refusal.
- `unknown` is inconclusive; timeout does not mean filtering.
- `error` is a local/worker probe failure.
- Service hints do not confirm protocols; banners do not confirm products.
- Asset IDs identify scoped address observations, not physical devices.
- Discovery observations preserve stable probe results. No response, timeout,
  unsupported tooling and probe errors never mean that an address is offline.
- TCP fallback is opt-in. `connected` and `connection_refused` only establish a
  response from that address during the measured probe; timeout is inconclusive.
- TLS metadata comes from an active, bounded handshake without SNI or certificate
  validation. Certificate hashes do not prove identity, ownership or security.
- PTR observations are untrusted aliases and never device identity or ownership.
  System-resolver timeouts are best-effort and recorded as such.

FOREX retains responsibility for correlation, risk and decisions. It must not
infer host-down from absent ICMP, a CVE from banner text, or risk from an open port.

Report 2.1 exposes support, enabled/eligible/attempted/observed counts, timeouts,
errors, truncation and configured-scope completeness per phase. These are
measurement-quality facts, never confidence or risk scores. Neighbor, HTTP and
candidate-relation evidence remain untrusted and do not establish identity.

Feed 1.0 provides compact coverage, asset and endpoint summaries with opaque
evidence/report references. FOREX may ingest it first and resolve the full report
when necessary. Hash-only output remains correlatable and is not anonymization.
