# Automated Python PCAP Analyzer & Threat Parser

[![CI/CD Pipeline](https://github.com/defensive-sec/pcap-threat-analyzer/actions/workflows/ci.yml/badge.svg)](.github/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)](CHANGELOG.md)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Security Focus: Defensive](https://img.shields.io/badge/Focus-Defensive%20Security%20%26%20SOC-green.svg)](#security-scope)
[![Docker Ready](https://img.shields.io/badge/Docker-Non--Root%20Multi--Stage-2496ED.svg)](Dockerfile)

A production-grade, offline network packet analysis, forensic intelligence, and threat-detection engine developed in Python and React/TypeScript. Designed for SOC analysts, digital forensics investigators, and threat hunters, it ingests `.pcap` and `.pcapng` capture files, dissects multi-layer protocols, tracks conversation flows, evaluates deterministic security heuristics, extracts observable Indicators of Compromise (IOCs), and compiles structured SIEM-ready JSON alongside formal 12-section technical investigation reports.

---

## Table of Contents

- [Overview](#overview)
- [Quick Start: Docker (Recommended)](#quick-start-docker-recommended)
- [Quick Start: Non-Docker Local Setup](#quick-start-non-docker-local-setup)
- [Public Demo vs Local Forensic Execution](#public-demo-vs-local-forensic-execution)
- [Key Features](#key-features)
- [DevSecOps & Production Hardening](#devsecops--production-hardening)
- [Architecture & Design](#architecture--design)
- [Environment-Aware Profiles](#environment-aware-profiles)
- [Command-Line Usage](#command-line-usage)
- [Detection Rules & Heuristics](#detection-rules--heuristics)
- [Repository Structure](#repository-structure)
- [Testing & Synthetic Fixtures](#testing--synthetic-fixtures)
- [Documentation Index](#documentation-index)
- [Disclaimer & License](#disclaimer--license)

---

## Quick Start: Docker (Recommended)

The entire full-stack platform (FastAPI backend + unprivileged Nginx static frontend) can be deployed with Docker Compose:

```bash
# 1. Clone the repository
git clone <YOUR_REPOSITORY_URL>
cd pcap-threat-analyzer

# 2. Configure environment variables
cp .env.example .env

# 3. Launch the container stack
docker compose up --build
```

Access the services:
- **Analyst Workspace UI**: `http://localhost:3000`
- **Backend API & Health**: `http://localhost:8000/health`
- **Interactive OpenAPI Docs**: `http://localhost:8000/docs` (in development mode)

---

## Quick Start: Non-Docker Local Setup

### Backend (Python 3.10+)

```bash
# 1. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt -r requirements-dev.txt

# 3. Run full test suite (44 unit tests)
PYTHONPATH=src python3 -m unittest discover tests

# 4. Analyze a capture via CLI
PYTHONPATH=src python3 -m src.pcap_analyzer.cli examples/syn_port_scan.pcap \
  --profile enterprise \
  -o reports/analysis.json \
  -r reports/investigation_report.txt \
  --iocs reports/iocs.json
```

### Frontend (Node 20+)

```bash
# 1. Install dependencies
npm ci

# 2. Start developer server (port 3000)
npm run dev

# 3. Compile production bundle
npm run build
```

---

## Public Demo vs Local Forensic Execution

| Environment | Purpose | Upload Policy | Data Privacy Boundary |
| :--- | :--- | :--- | :--- |
| **Public Portfolio Demo** | Demonstration & evaluation | **Disabled by default / Synthetic Only** | Uses pre-packaged synthetic captures (`syn_port_scan`, `dns_tunneling`, `cleartext`, `corporate_baseline`). Zero confidential packet data is uploaded or stored. |
| **Local Forensic Deployment** | Active incident triage | **Enabled (Protected)** | Runs on analyst workstation or internal LAN behind strict authentication. Capture files stay in isolated local sandbox `data/analyses/<id>/`. |

> **Operational Warning**: Never expose an unauthenticated public PCAP analysis service to the open internet. Real PCAP captures often contain cleartext credentials, API tokens, internal hostnames, and sensitive operational traffic.

---

## Overview

Modern Security Operations Centers (SOCs) and incident responders regularly encounter offline packet captures from firewalls, network taps, and endpoint sensors during breach triage. Manually sifting through thousands of packets in Wireshark is time-consuming and prone to human oversight.

The **Automated Python PCAP Analyzer & Threat Parser** solves this challenge by delivering a deterministic, rule-based packet parser and anomaly engine. Rather than relying on unreliable black-box AI models for raw parsing, this engine performs protocol dissection, flow reassembly, deep protocol intelligence (DNS, HTTP, TLS), and statistical baseline comparisons to produce actionable, evidence-backed security findings.

---

## Key Features

- **Multi-Engine Dissection Architecture**:
  - **Native Engine**: Zero-dependency RFC parser using pure-Python binary `struct` unpacking for libpcap and PCAPNG formats.
  - **Scapy Engine**: Deep layer inspection utilizing Scapy's packet dissection routines.
  - **PyShark Engine**: Optional Wireshark/tshark dissector integration for specialized protocol trees.
- **Full-Spectrum Protocol Dissection**:
  - **Layer 2 (Data Link)**: Ethernet II, 802.1Q VLAN tagging, ARP.
  - **Layer 3 (Network)**: IPv4, IPv6, ICMP (Echo Request/Reply, Unreachable, TTL Exceeded).
  - **Layer 4 (Transport)**: TCP (flag tracking, sequence numbers, handshake reconstruction), UDP.
  - **Layer 7 (Application)**: DNS (queries, responses, decompression pointers), cleartext HTTP (methods, URIs, Host/User-Agent headers, status codes), and TLS (record types, versions, ClientHello Server Name Indication / SNI).
- **Stateful Flow & Conversation Tracking**:
  - Reconstructs unidirectional and bidirectional IP conversations (`src_ip:src_port -> dst_ip:dst_port [proto]`).
  - Monitors TCP 3-way handshake completion (`SYN` -> `SYN-ACK` -> `ACK`) to differentiate established sessions from reconnaissance probes.
  - Computes traffic velocity metrics including Packets Per Second (PPS) and Bytes Per Second (BPS).
- **Observable IOC Extraction**:
  - Automatically isolates and deduplicates network indicators: IPv4/IPv6 endpoints, domains, full URLs, hostnames, emails, and checksums.
  - Cross-references occurrences with first-seen/last-seen timestamps and packet references.
- **Environment-Aware Threshold Profiles**:
  - Pre-tuned profiles for `default`, `home_lab`, `enterprise`, and `high_volume` deployments.
  - External JSON configuration support for custom SOC tuning.
- **Dual Reporting & Forensic Manifest**:
  - **Machine-Readable JSON**: Standardized schema for ingestion into Splunk, Elastic SIEM, or automated pipelines.
  - **Human-Readable 12-Section Investigation Report**: Formatted text report matching professional incident response documentation standards, complete with SHA-256 capture hashing.

---

## Stage 2 Enhancements

Stage 2 elevates the analyzer into a comprehensive SOC forensics tool:

1. **Dedicated Protocol Analyzers**:
   - `DNSAnalyzer`: Tracks transaction IDs, record types, response codes (NXDOMAIN/SERVFAIL), query velocities, and Shannon entropy for DGA/tunneling detection.
   - `HTTPAnalyzer`: Audits cleartext web traffic, flags automated scanners (sqlmap, Nikto, Nessus, Nmap), tracks URI path distributions, and inspects HTTP verbs.
   - `TLSAnalyzer`: Categorizes TLS versions (TLS 1.0/1.1/1.2/1.3), extracts ClientHello SNI hosts, and identifies deprecated cryptographic protocols.
2. **IOC Extraction Engine (`src/pcap_analyzer/iocs.py`)**:
   - Discovers and deduplicates network artifacts across packet headers, DNS queries, HTTP headers, and TLS handshakes.
   - Exports dedicated IOC JSON via `--iocs <path>`.
3. **Advanced Flow Intelligence**:
   - Classifies flow types: normal TCP sessions, incomplete connection attempts, high-frequency bursts, interactive sessions, and data transfers.
   - Tracks TCP resets (`RST`), SYN-ACK completion ratios, and directional packet counts.
4. **Forensic Integrity Manifest**:
   - Calculates SHA-256 hashes of input PCAPs to maintain chain of custody in forensic reporting.
5. **Actionable Threat Detections**:
   - Every alert references exact packet numbers, rule IDs, confidence scores, analyst recommended next steps, and forensic limitations.
   - Rules 001 through 011 cover port scanning, connection flooding, DNS tunneling, unencrypted protocols, automated scanners, and legacy encryption.

---

## Architecture & Design

The analyzer follows a modular, decoupled dataflow architecture:

```
                    PCAP / PCAPNG
                          │
                          ▼
                  ┌───────────────┐
                  │ Packet Parser │
                  └───────┬───────┘
                          │
          ┌───────────────┼────────────────┐
          ▼               ▼                ▼
       Protocols        Flows          Metadata
          │               │                │
    ┌─────┼─────┐         │          ┌─────┴─────┐
    ▼     ▼     ▼         ▼          ▼           ▼
   DNS   HTTP   TLS    TCP/UDP      IOCs       Integrity
    │     │     │         │
    └─────┴─────┴─────────┴──────────┐
                                     ▼
                           Detection Engine
                                     │
                     ┌───────────────┼───────────────┐
                     ▼               ▼               ▼
                  Findings        Evidence       Severity
                     │               │               │
                     └───────────────┼───────────────┘
                                     ▼
                         JSON + Security Report
```

### Dataflow Breakdown

1. **PCAP / PCAPNG Ingestion**: Multi-format packet reader (`NativePcapReader`, `ScapyPcapReader`, `PySharkPcapReader`) streams raw packets.
2. **Packet Parser**: Decodes Layer 2 through Layer 7 frames into structured `PacketRecord` instances.
3. **Tripartite Analytical Branches**:
   - **Protocols (`DNS`, `HTTP`, `TLS`)**: Dedicated protocol analyzers parse application-layer transactions, record types, methods, URI paths, User-Agents, and TLS handshakes/ciphers.
   - **Flows (`TCP/UDP`)**: Flow engine reconstructs conversations, evaluates 3-way handshake completion, computes packet velocities (PPS/BPS), and classifies flow states.
   - **Metadata (`IOCs`, `Integrity`)**: Extracts and deduplicates observable network indicators (IPs, domains, URLs, hashes) and computes forensic SHA-256 capture hashes.
4. **Detection Engine**: Consumes protocol records and conversation flows to evaluate modular, evidence-based threat rules (`RULE-001` - `RULE-011`).
5. **Tripartite Finding Model**: Produces structured **Findings** accompanied by concrete numerical **Evidence** and calibrated **Severity** ratings.
6. **JSON + Security Report**: Exports SIEM-compatible JSON, formal 12-section incident investigation text reports, and standalone IOC manifests.

---

## Environment-Aware Profiles

Detection thresholds can be configured dynamically based on network context:

| Profile | Target Environment | Scanning Threshold | DNS Tunneling Threshold | Use Case |
| :--- | :--- | :--- | :--- | :--- |
| `default` | Standard Enterprise / Campus | 20 unique ports | Entropy ≥ 3.85, 5+ queries | General triage & CTF analysis |
| `home_lab` | SOHO / Small Virtual Lab | 8 unique ports | Entropy ≥ 3.60, 3+ queries | High sensitivity, minimal background noise |
| `enterprise` | Corporate Branch / Datacenter | 40 unique ports | Entropy ≥ 4.00, 10+ queries | Tolerant of management scans and high baseline |
| `high_volume` | Backbone / Cloud Aggregator | 75 unique ports | Entropy ≥ 4.20, 25+ queries | Low false-positive rate on high-bandwidth links |

Profiles are loaded via the `--profile <name>` flag or custom JSON config files in `/config/`.

---

## Security Scope

This tool is strictly a **defensive cybersecurity analysis and forensic inspection application**.

- **Intended Use**: SOC incident response, network troubleshooting, threat hunting, forensic packet examination, blue-team training, and defensive research.
- **Strict Boundaries**:
  - No packet injection or manipulation.
  - No active exploitation or offensive traffic generation.
  - No external telemetry, third-party API calls, or cloud lookups.
  - Pure offline execution ensuring zero risk of data leakage.

---

## Installation

### Prerequisites
- Python 3.10 or higher.
- Standard POSIX or Windows operating environment.

### Setup
Clone the repository and install in development mode:

```bash
git clone https://github.com/your-username/pcap-threat-analyzer.git
cd pcap-threat-analyzer

# Optional virtual environment
python3 -m venv venv
source venv/bin/activate

# Install requirements
pip install -r requirements.txt
```

*Note: The native parser operates with zero external dependencies.*

---

## Command-Line Usage

### Basic Capture Triage
```bash
python3 -m pcap_analyzer capture.pcap
```

### Environment Profiles
Analyze a capture using the `home_lab` profile (tighter thresholds for small labs):
```bash
python3 -m pcap_analyzer capture.pcap --profile home_lab
```

### Full Forensic Export (JSON, Report & IOCs)
```bash
python3 -m pcap_analyzer \
  -i capture.pcap \
  -o reports/analysis.json \
  -r reports/investigation_report.txt \
  --iocs reports/iocs.json \
  --profile enterprise \
  --hash
```

### Command-Line Options
```text
positional arguments:
  pcap_file             Path to the PCAP or PCAPNG capture file to analyze.

options:
  -h, --help            show this help message and exit
  -i INPUT_FILE, --input INPUT_FILE
                        Alternative flag to specify input capture file path.
  -o JSON_OUTPUT, --output JSON_OUTPUT, --json JSON_OUTPUT
                        Path to write structured JSON analysis report.
  -r REPORT_OUTPUT, --report REPORT_OUTPUT
                        Path to write 12-section human-readable report (.txt).
  --iocs IOCS_OUTPUT    Path to write extracted Indicators of Compromise JSON file.
  -p {default,home_lab,enterprise,high_volume}, --profile {default,home_lab,enterprise,high_volume}
                        Environment-aware detection profile.
  -c CONFIG_FILE, --config CONFIG_FILE
                        Path to custom JSON configuration file overriding detection thresholds.
  --hash                Explicitly print the capture file SHA-256 integrity hash.
  --engine {auto,native,scapy,pyshark}
                        Packet dissection engine: 'auto' (default), 'native', 'scapy', or 'pyshark'.
  --max-packets MAX_PACKETS
                        Limit number of packets parsed (useful for massive capture triage).
  -v, --verbose         Enable verbose debug logging.
  -q, --quiet           Suppress console progress banners; output errors only.
  --version             show program's version number and exit
```

---

## Detection Rules & Heuristics

| Rule ID | Name | Severity | Category | Description |
| :--- | :--- | :--- | :--- | :--- |
| `RULE-001` | TCP Port Scanning | HIGH | Reconnaissance | Identifies vertical, horizontal, or hybrid SYN scanning probes with incomplete handshakes. |
| `RULE-002` | TCP SYN Flood | HIGH | DoS / Traffic Volume | Detects high-rate SYN packets with negligible handshake completion. |
| `RULE-003` | Unusual Port Usage | MEDIUM | Protocol Anomaly | Flags known administrative/database services running on non-standard ports. |
| `RULE-004` | DNS Query Volume Anomaly | MEDIUM | DNS Anomaly | Detects anomalous volumes of DNS resolution requests exceeding baseline. |
| `RULE-005` | Potential DNS Tunneling | HIGH | DNS Anomaly | Detects high-entropy subdomains and long QNAMEs indicative of C2 data exfiltration. |
| `RULE-006` | Excessive Connection Failures | LOW | Connection Anomaly | Identifies hosts generating repeated failed connections or RST bursts. |
| `RULE-007` | ICMP Flood Anomaly | MEDIUM | ICMP Anomaly | Detects excessive ICMP Echo Request rates indicative of ping sweeps or DoS. |
| `RULE-008` | Cleartext Protocol In Transit | LOW | Cleartext Communication| Identifies unencrypted protocol traffic (HTTP, Telnet, FTP) exposing headers. |
| `RULE-009` | HTTP Security Observation | MEDIUM / HIGH | HTTP Security | Flags automated scanner User-Agents (sqlmap, nikto, nessus) and abnormally long URIs. |
| `RULE-010` | TLS Security Observation | MEDIUM | TLS Security | Detects deprecated TLS versions (TLS 1.0, TLS 1.1, SSL 3.0) and missing SNI. |
| `RULE-011` | High Unique DNS Domain Count | LOW | DNS Anomaly | Detects hosts querying an excessive count of distinct second-level domains (DGA activity). |

---

## Sample Output & Forensic Reports

### Terminal Console Output
```text
======================================================================
 PCAP Threat Analysis Complete
======================================================================
 Target File:       mixed_forensics.pcap
 Profile:           home_lab [built-in (home_lab)]
 SHA-256 Hash:      df85f5e20a241c3d30de7a5436b75d8ca179b9d739b6b31ca31d06b7e4f08515
 Total Packets:     30
 Total Bytes:       2.77 KB
 Duration:          00:04.000
 Engine Used:       Native v2.0.0
 Unique Endpoints:  7 Sources -> 7 Destinations
 Active Flows:      22
 Extracted IOCs:    11 IPs | 9 Domains | 3 URLs
----------------------------------------------------------------------
 Security Findings: 7
  01. [HIGH]     Automated security scanner User-Agent signature observed
      Rule ID:     RULE-009 (HTTP Security Observation)
      Confidence:  0.90
      Packet(s):   28, 29
  02. [HIGH]     Potential network scanning activity observed
      Source:      10.0.0.99
      Rule ID:     RULE-001 (Reconnaissance)
      Confidence:  0.88
      Packet(s):   7, 8, 9, 10, 11...
  03. [HIGH]     Potential DNS tunneling indicators observed
      Source:      192.168.10.45
      Rule ID:     RULE-005 (DNS Anomaly)
      Confidence:  0.84
      Packet(s):   22, 23, 25, 26
  04. [MEDIUM]   Legacy TLS 1.0 protocol negotiation observed
      Rule ID:     RULE-010 (TLS Security Observation)
      Confidence:  0.92
      Packet(s):   30
======================================================================
```

### Extracted IOCs JSON Format
```json
{
  "domains": [
    {
      "type": "domain",
      "value": "v7x9k3m2p8q1w4z6.exfil-stage.tunnel-sec.com",
      "source": "DNS Query",
      "first_seen": 3.0,
      "last_seen": 3.0,
      "packet_count": 1,
      "context": {
        "sample_packets": [22],
        "contexts": ["DNS Query Type: A"]
      }
    }
  ],
  "urls": [
    {
      "type": "url",
      "value": "http://intranet.local/admin/login.php?id=1' UNION SELECT 1,2,3--",
      "source": "HTTP Request Line",
      "first_seen": 4.1,
      "last_seen": 4.1,
      "packet_count": 1,
      "context": {
        "sample_packets": [28],
        "contexts": ["Method: GET", "Host: intranet.local"]
      }
    }
  ]
}
```

---

## Repository Structure

```
pcap-threat-analyzer/
├── README.md                     # Comprehensive project documentation
├── LICENSE                       # Apache 2.0 open-source license
├── requirements.txt              # Core runtime dependencies
├── pyproject.toml                # Standard PEP 517/621 packaging metadata
│
├── config/                       # Environment-aware detection profiles
│   ├── default.json              # Standard enterprise baseline
│   ├── home_lab.json             # High-sensitivity lab profile
│   ├── enterprise.json           # Scaled threshold profile
│   └── high_volume.json          # High-throughput backbone profile
│
├── src/
│   └── pcap_analyzer/
│       ├── __init__.py           # Package exports and version
│       ├── __main__.py           # Module invocation wrapper
│       ├── cli.py                # Command-line interface with --profile, --iocs, --hash
│       ├── analyzer.py           # Pipeline coordinator with SHA-256 integrity
│       ├── parser.py             # Binary libpcap and PCAPNG readers
│       ├── protocols.py          # L2, L3, L4, L7 protocol decoders
│       ├── dns_analyzer.py       # Deep DNS metrics, QNAMEs, and Shannon entropy
│       ├── http_analyzer.py      # Cleartext HTTP verbs, URIs, and scanner signatures
│       ├── tls_analyzer.py       # TLS records, SNI hostnames, and deprecated versions
│       ├── iocs.py               # Indicator of Compromise extraction and deduplication
│       ├── statistics.py         # Handshake state tracking, PPS/BPS, flow classification
│       ├── detections.py         # Deterministic detection rules (RULE-001 - RULE-011)
│       ├── models.py             # Typed dataclasses (DNSRecord, HTTPRecord, TLSRecord, IOC)
│       ├── reporting.py          # 12-section technical investigation text & JSON reports
│       ├── utils.py              # Cryptographic hashing, entropy, and formatting tools
│       └── config.py             # Config schema and profile loaders
│
├── tests/
│   ├── __init__.py
│   ├── generate_test_pcaps.py    # Synthetic RFC-compliant PCAP fixture generator
│   ├── test_parser.py            # Unit tests for packet decoding
│   ├── test_statistics.py        # Unit tests for flow state tracking
│   ├── test_detections.py        # Unit tests for threat detection heuristics
│   ├── test_reporting.py         # Unit tests for report formats
│   ├── test_stage2.py            # Stage 2 integration tests (IOCs, profiles, new rules)
│   └── fixtures/                 # Reproducible synthetic test PCAPs
│       ├── normal_traffic.pcap
│       ├── scan_traffic.pcap
│       ├── dns_tunneling.pcap
│       ├── http_cleartext.pcap
│       ├── tls_legacy.pcap
│       └── mixed_forensics.pcap
│
└── reports/                      # Sample generated analysis reports and IOC exports
    ├── analysis.json
    ├── investigation_report.txt
    └── iocs.json
```

---

## Testing & Synthetic Fixtures

Run the test suite using Python's standard `unittest`:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -p "test_*.py" -v
```

All 44 unit and integration tests validate:
- Binary packet parsing accuracy across Ethernet, IPv4, TCP, UDP, ICMP, DNS, HTTP, and TLS.
- Handshake state machine accuracy across established, incomplete, and reset flows.
- Shannon entropy calculations and threshold-based DNS tunneling detection.
- IOC deduplication, timestamp aggregation, and JSON schema conformity.
- Profile loading and threshold override logic.
- Input validation, path traversal defense, and ephemeral data retention.
- End-to-end execution against reproducible synthetic PCAPs.

---

## Documentation Index

Comprehensive engineering, DevSecOps, and deployment specifications:

- **[Portfolio Case Study](docs/portfolio-case-study.md)**: High-density portfolio documentation, architecture breakdown, and interview guide.
- **[Security Hardening & Threat Model](docs/security-hardening.md)**: Input sanitization, path traversal defenses, sandboxed storage, and security headers.
- **[DevSecOps & Automated Quality Pipeline](docs/devsecops.md)**: CI workflows, Ruff linter, mypy static typing, coverage, and Gitleaks secret scanning.
- **[Deployment & Architecture Strategies](docs/deployment.md)**: Multi-stage Docker, production reverse proxies, and portfolio demo boundaries.
- **[Production Release Checklist](docs/release-checklist.md)**: Step-by-step verification checklist prior to tagging a production release.
- **[Security Policy & Reporting](SECURITY.md)**: Vulnerability disclosure and defensive operational boundaries.
- **[Changelog & Release Notes](CHANGELOG.md)**: Version history conforming to Keep a Changelog.

---

## Forensic Limitations & Operational Boundaries

1. **Heuristic Nature**: Detections represent deterministic statistical anomalies. Alerts reflect suspicious patterns, not definitive proof of compromise. Analysts must cross-correlate alerts with host endpoint EDR data.
2. **Payload Visibility**: In encrypted TLS/HTTPS streams, inspection is restricted to unencrypted handshake metadata (ClientHello SNI, negotiated versions, cipher suites).
3. **Capture Completeness**: Truncated frames (`snaplen` limitations) may prevent parsing of deep application layer payloads. Such occurrences are cataloged in Section 11 of the technical report.

---

## Disclaimer & License

### Disclaimer
This software is provided for defensive cybersecurity analysis, research, and educational purposes. It is a forensic aid and does not substitute for a certified Intrusion Detection System (IDS) or professional human analyst investigation.

### License
Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) for details.
