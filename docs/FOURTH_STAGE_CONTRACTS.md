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
