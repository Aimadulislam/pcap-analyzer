# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- PCAPNG enhanced block comments extraction.
- PCAP export filter helper for targeted Wireshark carving.

---

## [0.1.0] - 2026-09-24

### Added
- **Core Dissection Engine**:
  - Native libpcap C-struct binary reader with zero external binary runtime requirement.
  - Scapy and PyShark fallback adapters with deep packet protocol inspection.
  - Layer 2–7 protocol demuxing: Ethernet, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP, and TLS.
  - Bidirectional 5-tuple conversation flow reconstruction with TCP handshake state tracking.
- **Deterministic Threat Detection Heuristics**:
  - 11 evidence-backed security observation rules (`RULE-001` through `RULE-011`).
  - Full authentic MITRE ATT&CK technique alignments (`T1046`, `T1499`, `T1571`, `T1071.004`, `T1572`, `T1040`, `T1595.002`, `T1573`, `T1568.002`).
  - Tunable detection configuration profiles: `default`, `home_lab`, `enterprise`, and `high_volume`.
- **Forensic Reporting & Observables**:
  - 12-section technical incident investigation text report generator.
  - Automated IOC harvester generating categorized observable manifests (`iocs.json`).
  - Cryptographic SHA-256 capture integrity verification.
- **DevSecOps & API Architecture**:
  - Versioned REST API (`/api/v1/...`) with `/health` and `/ready` system status probes.
  - Request ID tracking (`X-Request-ID`) and security headers (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`).
  - Configurable upload size limit (HTTP 413) and analysis concurrency throttling.
  - Sandboxed analysis storage manager with automated data retention cleanup script (`scripts/cleanup_data.py`).
  - Multi-stage non-root production Dockerfiles (`Dockerfile`, `frontend/Dockerfile`) and Docker Compose stacks.
  - Comprehensive GitHub Actions CI/CD pipeline covering Python Ruff linting, mypy type checks, 31 pytest unit tests with coverage, and Gitleaks secret scanning.
- **SOC Analyst Web Interface**:
  - Dark cybersecurity analyst UI with zero-pill metadata discipline and high-contrast typography.
  - Forensic Evidence Drawer and ATT&CK alignment modal.
  - Deep 5-tuple flow inspection modal with Wireshark/tshark display filter generator.
  - Interactive technical architecture pipeline visualization and documentation browser.
  - Isolated static Demo Mode adapter with explicitly marked `DEMO DATA` indicators.
