# SCAN fifth-stage contracts

SCAN remains an evidence sensor. FOREX remains responsible for interpretation, correlation, scoring and decisions. This stage adds no exploitation, authentication, CVE matching, vulnerability scoring or remote FOREX transport.

`main.py` is a compatibility bootstrap. Legacy `TARGET ...` and explicit `scan TARGET ...` share the immutable configuration resolver and acquisition pipeline. Scan Plan 1.0 is deterministic, bounded and performs zero acquisition.

Report 2.2 adds Coverage 2.0, separate measurement/execution fingerprints, explicit partial termination, acquisition segments and baseline eligibility. Snapshot 1.2 accepts only complete baseline-eligible Report 2.2 documents. Feed 1.1 projects partial coverage without interpreting omissions. Validation Result 1.0 means contract conformance only. Migration Receipt 1.0 records hashes and `not_recorded` synthesis. Checkpoint 1.0 is neither report, snapshot nor outbox item. Outbox Item 1.0 embeds a validated immutable payload.

Includes cannot expand the canonical root target; exclusions win. `excluded_by_policy`, `budget_exhausted`, timeout and error are distinct. Coverage records selected, excluded, scheduled, completed, cancelled and not-started counts. The measurement fingerprint uses an explicit allowlist; runtime resource policy has a separate fingerprint.

Resumed reports contain acquisition segments, set `temporally_uniform` false and are not automatically baseline eligible. Resume is opt-in and incompatible state fails closed.

Writers use same-directory temporaries, file `fsync`, atomic replacement or exclusive creation, bounded readers and validated identifiers. Directory durability is best effort across Windows/WSL/Linux. Symlink roots are rejected; operational roots should avoid cloud-synchronized directories.

The outbox is local and at-least-once. FOREX deduplicates by deduplication key and content hash. ACK confirms delivery with a claim token; it does not mean truth, semantic acceptance, risk acceptance or a decision. Exactly-once is not promised.
