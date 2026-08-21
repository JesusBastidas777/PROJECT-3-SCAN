# SSH host-key evidence decision

SSH host-key collection is intentionally not implemented in the fourth stage.
Python's standard library does not implement SSH transport or key exchange. A
partial in-project SSH implementation would create disproportionate protocol,
cryptographic and portability risk. `ssh-keyscan` is not uniformly installed,
and a large SSH dependency is not justified for one additional weak signal.

A future version may define an optional, explicitly supported backend after an
independent dependency and portability decision. It must never authenticate,
send usernames or credentials, execute commands or treat a host key as proof of
identity, ownership or physical-device continuity. Until then coverage records
SSH as unsupported/not implemented rather than inventing target evidence.
