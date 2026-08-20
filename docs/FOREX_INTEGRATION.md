# SCAN to FOREX integration

Use `python3 src/main.py TARGET --output -` for frozen schema 1.0, or add
`--schema-version 2.0` for assets, precise observations, service hints,
fingerprints, capabilities and structured errors. Stdout remains one JSON
document; operational messages use stderr.

`--collect-banners` enables bounded passive reads only on endpoints observed
open. Banners are untrusted and potentially sensitive. SCAN does not follow
redirects, authenticate, send credentials, or pretend plain sockets support TLS.

`--history-dir PATH` stores immutable schema-2.0 snapshots. Comparisons cover
only common measured scope: missing data and unknown/error transitions remain
indeterminate. `--events-output PATH` writes bounded event arrays; validate
`event_schema_version` independently and deduplicate using `deduplication_key`.

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

FOREX retains responsibility for correlation, risk and decisions. It must not
infer host-down from absent ICMP, a CVE from banner text, or risk from an open port.
