# SCAN FOREX release candidate

- Public Python facade and workflow frozen at 1.0.
- Report 2.2 is explicit for FOREX; legacy Report 1.0 default is unchanged.
- Runtime defaults outside the source tree and exposes readiness, heartbeat,
  status, latest operational view and bounded history.
- One active scan is enforced with memory and portable file locks.
- Cancellation is cooperative between bounded acquisition phases.
- Publication is local, atomic and detectable; outbox remains opt-in,
  at-least-once and idempotent-consumer oriented.
- Rich UI is optional, bounded, read-only on refresh and contains no acquisition.
- No offensive capability, remote server, broker or shared database was added.

Known limitations: system ICMP portability remains platform-dependent; cancellation
waits for already-started bounded calls; runtime start is host-supervisor oriented;
cloud-synchronized directories are unsuitable for production runtime state.
