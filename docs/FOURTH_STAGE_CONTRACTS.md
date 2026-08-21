# SCAN fourth-stage evidence contracts

Report 2.1 adds an execution coverage model. Coverage describes runtime support,
configuration, bounded attempts and outcomes; it is neither risk nor a claim of
total network visibility. Unsupported capability describes the local runtime,
not the target.

Optional neighbor evidence reads an already-populated system table. It performs
no active ARP/NDP scan, sends no raw packets and does not treat cache absence as
host state. Linux prefers `ip -j neighbor show` and can fall back to
`/proc/net/arp`; native Windows uses structured PowerShell output. WSL records
`network_context=wsl_guest` and never consults the Windows host automatically.

Link-layer addresses are sensitive. `--neighbor-privacy hash-only` is the
default; hashes remain correlatable and are not anonymization. Cache entries,
states and link-layer addresses do not prove current reachability, ownership or
physical-device identity.

HTTP evidence is opt-in and bounded. It sends `HEAD /` with an IP-literal Host,
does not follow redirects, retain cookies, authenticate or crawl. Explicit
`head-get` mode uses a range-limited GET only after 405/501 and still enforces a
local body-prefix limit. Only allowlisted metadata and an optional prefix hash
are retained. Server, Location and response hashes are untrusted evidence and
do not confirm product, ownership, identity or vulnerability.

Report 2.1 candidate `evidence_clusters` preserve separate asset IDs and expose
their signal class, evidence references, limitations, ruleset and
contradictions. PTR or service hints alone never create a multi-address
relation. Every relation carries `physical_device_asserted=false`; FOREX remains
responsible for global correlation and interpretation.

Comparison 2.0 defaults to strict measurement-scope equivalence. A configuration
change produces an incomparable result rather than a network change.
`--policy common-scope` can expose a measured intersection and always labels it
partially comparable. Presentation settings have an independent fingerprint;
privacy, probe, port, timeout and limit changes remain measurement semantics.

Report 2.1 records the real discovery mode, a canonical effective configuration
and its fingerprint. Snapshot 1.1 wraps report 2.1 and adds independent
measurement/presentation fingerprints; snapshot 1.0 remains readable for report
2.0. Loaders discriminate and validate versions before accessing nested fields.

`SCAN query` and `SCAN history list/show` are bounded local readers. They perform
no discovery, endpoint, DNS, TLS, HTTP or neighbor probes. JSON query output is
versioned; NDJSON and text are deterministic projections. Inputs are size
limited, UTF-8 strict, version validated and reject symlinks by default.
