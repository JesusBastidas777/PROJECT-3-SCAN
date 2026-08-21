# Report schema migration: 1.0 to 2.0

Fifth-stage migrations use an explicit registry. Report 2.1 to 2.2 represents unavailable execution policy and acquisition segments as `not_recorded`; it never synthesizes evidence. Unsupported routes fail closed and inputs are not overwritten.

Schema 1.0 remains the default and preserves historical `hosts[].ports[]`
`OPEN`/`CLOSED`. Schema 2.0 is selected with `--schema-version 2.0`.

- `timestamp` becomes `started_at`; `completed_at` is added.
- `metadata` becomes `configuration` plus truthful `capabilities`.
- `hosts` becomes normalized `assets`; distinct addresses are not merged.
- `observations` distinguish `open`, `closed`, `unknown`, and `error`.
- Service names are hints; banners are explicitly untrusted.
- Stable scan, target, asset, observation and error identifiers aid correlation.

Never translate legacy `CLOSED` back into a precise 2.0 state: it historically
included refusal, timeout, unreachable and local failures. Report and event
contract versions evolve independently.

## Fourth-stage contracts

- Report 2.1 adds effective configuration, coverage, structured capability
  execution, passive neighbor evidence, bounded HTTP evidence and candidate
  relations. Report 1.0 remains frozen and report 2.0 remains readable.
- Snapshot 1.1 wraps report 2.1 with measurement/presentation fingerprints;
  snapshot 1.0 remains the report-2.0 format.
- Comparison 2.0 adds strict/common-scope policies and explicit comparability.
- Feed 1.0 is an independent compact projection. Event and batch 1.0 remain
  independently versioned and accept report 2.0 or 2.1 producers.
