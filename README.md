# SCAN

SCAN is a small network discovery and TCP port collection tool. It discovers
reachable hosts with ICMP, checks selected TCP ports, and emits deterministic,
versioned JSON. SCAN reports observed facts; it does not assess vulnerabilities,
assign risk, or contain artificial intelligence. FOREX or another downstream
system can consume the JSON and perform analysis separately.

Use SCAN only on systems and networks you own or are explicitly authorized to
test. Network scanning may be restricted by law, policy, or provider terms. The
operator is responsible for obtaining authorization and selecting a safe target
and concurrency level.

## Architecture

- `src/scanner/ping.py`: bounded ICMP probe execution.
- `src/scanner/discovery.py`: target validation and concurrent host discovery.
- `src/scanner/ports.py`: bounded IPv4/IPv6 TCP connection scanning.
- `src/scanner/report.py`: schema-v1 summaries and JSON serialization.
- `src/main.py`: argument parsing, orchestration, output, and exit codes.

The scanner modules do not print progress. The CLI sends machine-readable JSON
to stdout only when requested and sends human-readable status or errors to
stderr.

## Requirements and installation

- Python 3.10 or newer.
- A POSIX-compatible system `ping` command. IPv6 discovery also requires the
  installed `ping` implementation to support `-6`.
- No third-party Python packages.

Clone the repository and run it directly:

```bash
git clone <repository-url>
cd SCAN
python3 src/main.py --help
```

## Usage

Basic IPv4 scan using the default common TCP ports:

```bash
python3 src/main.py 192.168.1.0/24
```

Single IPv4 or IPv6 host:

```bash
python3 src/main.py 127.0.0.1/32
python3 src/main.py ::1/128
```

Choose ports and resource limits:

```bash
python3 src/main.py 192.168.1.0/24 \
  --ports 22,80,443 \
  --workers 64 \
  --ping-timeout 1 \
  --connect-timeout 1 \
  --max-hosts 4096
```

Options:

- `--ports`: comma-separated TCP ports from 1 through 65535. Duplicates are
  removed while retaining their first position.
- `--workers`: global concurrency bound from 1 through 256.
- `--ping-timeout`: positive ICMP timeout in seconds.
- `--connect-timeout`: positive TCP connection timeout in seconds.
- `--max-hosts`: safety limit. Targets with more candidate hosts are rejected
  before discovery begins.
- `--output`: JSON file path, or `-` for JSON on stdout. The default is
  `results/scan.json` relative to the repository, regardless of the current
  working directory. Explicit relative paths are resolved from the caller's
  current directory.

CIDR host bits are normalized. For example, `192.168.1.7/24` scans the canonical
network `192.168.1.0/24`. Large targets such as `0.0.0.0/0` are rejected unless
the operator deliberately raises `--max-hosts`.

## Automation and FOREX

Use `--output -` for a clean JSON stream:

```bash
python3 src/main.py 127.0.0.1/32 --ports 22,80 --output -
```

It can be validated or piped to an authorized downstream consumer:

```bash
python3 src/main.py 127.0.0.1/32 --output - | python3 -m json.tool
python3 src/main.py 192.168.1.0/24 --output - | forex-input-command
```

When stdout is selected it contains only one JSON document. Operational errors
remain on stderr. SCAN does not implement FOREX and does not analyze the report.

## JSON schema v1

Every report contains:

- `schema_version`: currently `"1.0"`.
- `scanner`: scanner name and implementation version.
- `network`: canonical network retained for compatibility.
- `target`: original input, canonical network, IP version, and candidate count.
- `timestamp`: scan start time in UTC ISO-8601 format.
- `duration_ms`: discovery and TCP scan duration measured with a monotonic clock.
- `summary`: active/scanned hosts, scanned ports, open/closed totals, and errors.
- `hosts`: ordered host records.
- `metadata`: discovery method, requested ports, timeouts, workers, and host limit.

Each host retains the established fields `ports`, `open_ports`, `open_count`, and
`closed_count`, and adds `error_count`. TCP results retain `port`, `protocol`, and
the status values `OPEN` or `CLOSED`. A report with no active hosts is still a
complete schema-v1 document with empty `hosts` and zero summary counters.

Schema 1.0 remains the CLI default and is frozen for compatibility. Select the
evidence-rich report contract with `--schema-version 2.0`. Version 2.0 separates
assets, observations, stable errors, actual capabilities and scan configuration.

`--history-dir PATH` opt-in stores immutable schema-2.0 snapshots plus an atomic
index. History is never deleted automatically and may retain sensitive banners;
operators must apply suitable permissions and retention policy.

Snapshot comparisons operate only on common measured scope. Missing endpoints and
unknown/error transitions are explicitly indeterminate; they never assert that a
host is offline, a timeout is filtering, or a changed banner is an update.

`--events-output PATH` writes a bounded array of versioned FOREX events for a
schema-2.0 scan. Events are deterministic and idempotent, remain local, and state
truncation explicitly. They contain evidence, never vulnerability conclusions.

Detailed integration and migration guidance is in `docs/FOREX_INTEGRATION.md`
and `docs/SCHEMA_MIGRATION.md`.

## Exit codes

- `0`: scan and output completed successfully.
- `1`: operational, scanner, or filesystem failure.
- `2`: invalid CLI usage or unsafe/invalid target.
- `130`: interrupted by the operator.

## Tests

The suite uses only the Python standard library and does not scan the Internet:

```bash
python3 -m compileall -q src
python3 -m unittest discover -s tests -v
```

## Known limitations

- ICMP may be blocked even when a host is online; such a host will not proceed
  to TCP scanning.
- For compatibility, TCP refusal, filtering, and connection errors are currently
  represented as `CLOSED`; SCAN does not claim why a connection failed.
- ICMP flags target POSIX `ping`/iputils behavior and are not a native Windows
  implementation.
- SCAN performs connection checks only. It does not identify services, versions,
  CVEs, vulnerabilities, or security risk.
- Internally SCAN distinguishes open, closed, unknown, and probe-error TCP
  observations. Schema 1.0 retains its historical OPEN/CLOSED projection.
- Conventional service names are low-confidence port-registry hints only; they do
  not confirm which protocol or product is listening.
- `--collect-banners` enables passive reads only on observed open endpoints. Banner
  bytes are bounded, untrusted, never authenticated, and schema 1.0 omits them.
- Basic fingerprints are deterministic rules over collected evidence. They expose
  their basis, confidence and rule ID and do not claim OS, product, CVE or risk.
- Inventory asset IDs identify an address observation within a canonical target;
  they are not permanent identities and distinct addresses are never auto-merged.
