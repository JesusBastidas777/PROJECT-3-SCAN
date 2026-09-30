







# PROJECT-3-SCAN

Network Discovery & Scanning system built in Python for host discovery, TCP port scanning, structured network intelligence, runtime resilience, and future integration with PROJECT FOREX.

**Status:** SCAN V1 Release Candidate
**FOREX contract:** 2.2
**Platform:** Linux / WSL
**Language:** Python

## Overview

PROJECT-3-SCAN is a modular network discovery and scanning system developed as a cybersecurity engineering project.

The system discovers active hosts within a target network, performs TCP port scanning, organizes results by host and network, and exposes structured network state through a stable local interface designed for PROJECT FOREX integration.

The project was designed around several engineering priorities:

* Modular network discovery
* TCP service enumeration
* Structured scan results
* Host-level and network-level summaries
* Concurrent port scanning
* Runtime resilience
* Reproducible validation
* Clear separation between scanning, runtime, and integration layers
* Stable FOREX integration boundaries

SCAN operates locally and does not require cloud services or external scanning platforms.

## Architecture

```text
                 Target Network
                       │
                       ▼
                Host Discovery
                       │
                       ▼
                Active Hosts
                       │
                       ▼
                TCP Port Scanner
                       │
              ┌────────┴────────┐
              ▼                 ▼
        Host-Level Data    Network Summary
              │                 │
              └────────┬────────┘
                       ▼
               Structured State
                       │
              ┌────────┴────────┐
              ▼                 ▼
        Local Operations    FOREX Contract
              │                 │
              ▼                 ▼
          CLI / GUI        Structured State
```

The architecture keeps host discovery, port scanning, result processing, runtime state, and FOREX publication separated so that each component can evolve independently.

## Discovery Capabilities

PROJECT-3-SCAN discovers active hosts within a target network using ICMP-based host discovery.

For each discovered host, the scanner records:

* IP address
* Host availability
* Scan state
* TCP port results
* Open port information
* Closed port information

The discovery layer is intentionally separated from the TCP scanning layer.

## TCP Scanning

SCAN performs TCP connect-based scanning against a defined set of commonly used service ports.

The default port set includes:

* FTP — 21
* SSH — 22
* Telnet — 23
* SMTP — 25
* DNS — 53
* HTTP — 80
* POP3 — 110
* IMAP — 143
* HTTPS — 443
* SMB — 445
* RDP — 3389

Each result records:

```text
port
protocol
status
```

The scanner also supports concurrent port execution so multiple TCP probes can be performed efficiently instead of processing every port strictly sequentially.

## Structured Network State

SCAN produces structured JSON state containing both detailed scan information and higher-level summaries.

Host-level information includes:

```text
host
ports
open_ports
open_count
closed_count
```

Network-level information includes:

```text
network
active_hosts
total_open_ports
total_closed_ports
hosts
```

This structure allows another system to consume network state without having to parse terminal output.

## Runtime Resilience

The SCAN runtime is designed to preserve operational state and expose its current condition through a bounded local interface.

Runtime information can include:

* Scanner status
* Runtime health
* Heartbeat information
* Readiness state
* Current scan state
* Published network state
* Integration metadata

Operational state is kept separate from the source tree where appropriate.

## FOREX Integration

PROJECT-3-SCAN is designed to remain an independent cybersecurity component while exposing a stable local contract for PROJECT FOREX.

The current SCAN implementation uses the FOREX integration boundary to publish structured network information without requiring FOREX to directly depend on the internal implementation of the scanner.

Published information can include:

* Active hosts
* Open TCP ports
* Host-level summaries
* Network-level summaries
* Scanner health
* Runtime state
* Freshness metadata
* Readiness information

The integration contract is documented in:

```text
docs/
```

FOREX is designed to consume structured SCAN information while allowing PROJECT-3-SCAN to remain independently maintainable.

## PROJECT FOREX

PROJECT FOREX integrates independently developed cybersecurity components:

```text
PROJECT-1-EDR   → Endpoint Detection & Response
PROJECT-2-SOC   → Security Operations
PROJECT-3-SCAN  → Network Discovery & Scanning
                         │
                         ▼
                   PROJECT FOREX
```

FOREX is intended to consume structured information from these systems through defined integration boundaries.

Each project remains independently executable, testable, and maintainable.

## Supported Environment

The project is developed and tested using:

* Python 3.11+
* Linux
* WSL development environment
* IPv4 networks
* TCP/IP networking

Create a virtual environment:

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

Install project dependencies:

```bash
python3 -m pip install -r requirements.txt
```

## Running SCAN

The basic scanner entrypoint is:

```bash
python3 src/main.py <network>
```

Example:

```bash
python3 src/main.py 192.168.1.0/29
```

The scanner discovers active hosts, performs TCP port scanning, and writes structured results to:

```text
results/scan.json
```

The project also provides operational interfaces for runtime inspection and FOREX integration.

## Validation

The project includes automated tests covering core scanning components and application behavior.

Run the test suite with:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -v
```

The project should also be validated using a controlled network environment before operational use.

Only scan networks and systems for which you have authorization.

## Project Structure

```text
PROJECT-3-SCAN/
│
├── docs/
├── results/
├── src/
│   ├── main.py
│   ├── scanner/
│   │   ├── discovery.py
│   │   ├── ping.py
│   │   └── ports.py
│   └── utils/
│
├── tests/
├── main.py
├── README.md
└── requirements.txt
```

## Documentation

Additional engineering and integration documentation is available in:

```text
docs/
```

The documentation covers the scanner architecture, runtime behavior, integration boundaries, and validation information.

## Security Considerations

PROJECT-3-SCAN is a network security engineering tool.

Scanning can generate network traffic and may be detected or blocked by network security controls.

The scanner should only be used against networks and systems for which the operator has explicit authorization.

The project is intended for educational, engineering, testing, and authorized security assessment purposes.

## Current Status

PROJECT-3-SCAN has completed its development milestone and has been validated through its development history.

The project includes:

* Host discovery
* TCP port scanning
* Concurrent scanning
* Structured JSON results
* Host-level summaries
* Network-level summaries
* Runtime state
* Operational interfaces
* FOREX integration boundaries
* Automated tests
* GUI support

The project is considered a completed component of the PROJECT FOREX ecosystem.

## Roadmap

Future work may include:

* Additional protocol support
* Expanded service detection
* Deeper network intelligence
* Additional performance optimization
* Expanded automated validation
* Continued PROJECT FOREX integration

## Author

**Jesús Bastidas**

Mechatronics student focused on cybersecurity, systems engineering, networking, Linux, and Python.

PROJECT-3-SCAN was developed as part of my practical cybersecurity engineering work and as the third component of a larger set of independently developed security projects.

## License

This project is licensed under the MIT License.

See `LICENSE` for details.









