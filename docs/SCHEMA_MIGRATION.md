# Report schema migration: 1.0 to 2.0

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
