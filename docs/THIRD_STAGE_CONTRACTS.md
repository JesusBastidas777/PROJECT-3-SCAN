# SCAN third-stage contracts and operations

SCAN emits independently versioned report, snapshot, comparison, event and
event-batch documents. FOREX must validate each version independently and use
`deduplication_key` for at-least-once-friendly event ingestion. Report schema
1.0 remains frozen; report 2.0 additions are optional evidence fields.

Evidence classification:

- banners may contain arbitrary peer-provided text;
- certificate hashes and negotiated TLS metadata are untrusted and do not prove
  identity, ownership, security or vulnerability;
- PTR names are untrusted aliases and do not establish device identity;
- snapshots retain all enabled evidence until an explicit retention command;
- hash-only event export omits textual evidence but is not anonymization.

History retention is never automatic. `SCAN history retain` defaults to dry-run;
`--apply` is required to delete selected immutable files. Compare and history
commands do not perform network probes. Operators should use restrictive
filesystem permissions and retention appropriate to their environment.

The POSIX ICMP backend targets iputils-style flags. TCP, TLS and DNS use Python
standard-library facilities. System reverse-DNS timeout is best-effort. Windows,
macOS and BSD may expose different ICMP tooling; unsupported execution becomes
structured evidence rather than a host-state conclusion.
