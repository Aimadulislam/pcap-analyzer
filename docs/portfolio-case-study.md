# Cybersecurity Portfolio Case Study

## Project Title
**Automated Python PCAP Analyzer & Threat Parser**  
*Defensive Network Forensics & Evidence-Based Threat Analysis*

---

## 1. Project Positioning & Executive Summary

- **Primary Domain**: Defensive Cybersecurity, Network Forensics, SOC / Blue Team Operations, Detection Engineering, and Python Security Automation.
- **Scope Boundary**: An offline network-forensics platform that transforms raw packet captures (`.pcap` / `.pcapng`) into structured conversation flows, protocol telemetry, Indicators of Compromise (IOCs), and evidence-based security findings using configurable heuristic detection rules.
- **Anti-Marketing Discipline**: This application does *not* claim to be an "autonomous AI SOC", "malware execution sandbox", or "enterprise SIEM replacement". It is an evidence-first forensic tool built to accelerate human analyst triage without substituting analyst contextual judgment.

---

## 2. Descriptions (Portfolio, Resume & Social)

### Portfolio Short Description
> "Python-based PCAP analysis platform for network forensics, IOC extraction, flow analysis, and evidence-based threat detection."

### Portfolio Medium Description
> "Built a defensive PCAP analysis platform using Python, Scapy and PyShark to reconstruct network activity, extract IOCs, analyze protocols, and identify suspicious traffic patterns through configurable detection rules."

### Portfolio Technical Description
> "Engineered a modular PCAP/PCAPNG analysis platform with Python, Scapy, PyShark and FastAPI, combining protocol analysis, flow reconstruction, IOC extraction, configurable detection logic, reproducible synthetic testing, and a React-based analyst interface."

### Resume Project Entry
**Automated Python PCAP Analyzer & Threat Parser**
- Engineered a Python-based PCAP/PCAPNG analysis platform for network-forensics workflows, protocol inspection, flow reconstruction, and IOC extraction.
- Implemented configurable behavioral detection rules that transform observable network patterns into evidence-based analyst findings.
- Built a FastAPI backend and React/TypeScript analyst interface with investigation views for DNS, HTTP, TLS, network flows, findings, IOCs, and reporting.
- Added reproducible synthetic PCAP fixtures, automated testing, Docker deployment, and DevSecOps validation.

### LinkedIn Project Description
> I built the Automated Python PCAP Analyzer & Threat Parser, an offline network forensics platform for incident responders and SOC analysts.
>
> Ingesting raw PCAP/PCAPNG captures, the engine dissects Layer 2–7 protocols (Ethernet, IPv4/IPv6, TCP, UDP, ICMP, DNS, HTTP, TLS), reconstructs bidirectional 5-tuple conversation flows, extracts observable IOCs, and evaluates 11 deterministic heuristic detection rules across calibrated environment profiles.
>
> The stack combines a native C-struct unpacker and Scapy/PyShark engines with a FastAPI backend and a high-density React/TypeScript analyst console. Detections provide transparent packet indices and byte ratios aligned with MITRE ATT&CK techniques, supported by 44 automated unit tests, Docker containerization, and DevSecOps pipelines.

---

## 3. Technology Stack & Demonstrable Skills

| Category | Implemented Technologies |
| :--- | :--- |
| **Languages** | Python 3.10+, TypeScript 5 |
| **Network Analysis** | Native binary struct unpacker, Scapy, PyShark, tshark |
| **Backend & REST API** | FastAPI, Pydantic, Express, Node.js |
| **Frontend UI** | React 19, Vite, Tailwind CSS, Recharts, Lucide Icons |
| **Testing & CI** | unittest, pytest, 44 automated test fixtures |
| **DevSecOps** | GitHub Actions, Ruff, mypy, Gitleaks, pip-audit |
| **Containerization** | Docker (unprivileged non-root), Docker Compose |

### Relevant Skills
`Python` · `PCAP Analysis` · `Network Forensics` · `Network Security` · `Detection Engineering` · `IOC Extraction` · `SOC / Blue Team` · `FastAPI` · `React` · `Docker` · `DevSecOps`

---

## 4. End-to-End Forensic Architecture & Pipeline

```text
PCAP / PCAPNG Ingestion
       │
       ▼
Input Validation & SHA-256 Digest
       │
       ▼
Packet Parsing Engine (Native libpcap / Scapy)
       │
       ▼
Protocol Analysis (DNS, HTTP, TLS Dissectors)
       │
       ▼
5-Tuple Flow Reconstruction & TCP State Machine
       │
       ▼
IOC Harvester (IPs, Domains, URLs, Ports)
       │
       ▼
Detection Engine (11 Evidence-Based Rules)
       │
       ▼
Structured Alert Findings with Packet References
       │
       ▼
REST API (FastAPI / Express)
       │
       ▼
Analyst Interface (React / TypeScript SOC Console)
       │
       ▼
Incident Documentation (JSON & 12-Section Plaintext Report)
```

---

## 5. Detection Engineering & MITRE ATT&CK Context

Detections are deterministic, mathematical evaluations of observable traffic invariants. Every alert includes exact packet indices, timestamps, and confidence ratings.

### Sample Implemented Rules

1. **RULE-001 — Potential TCP SYN Scanning Pattern**
   - **Observed Behavior**: High volume of unacknowledged TCP SYN connection attempts across diverse destination ports with low completion ratio.
   - **Evidence Captured**: `syn_packets_transmitted`, `unique_destination_ports_targeted`, `completed_handshakes`, `handshake_completion_ratio (<= 15%)`.
   - **Potential Interpretation**: Network reconnaissance, host discovery sweep, or port mapping.
   - **False-Positive Considerations**: Legitimate vulnerability scanners (e.g. Tenable Nessus, Qualys), network discovery tools, or internal load balancers.
   - **MITRE ATT&CK Association**: Potential association with `T1046: Network Service Discovery`.

2. **RULE-004 — High-Entropy DNS Query (Tunneling / DGA)**
   - **Observed Behavior**: DNS query domain with Shannon entropy $\ge 3.8$ bits/char and length $\ge 25$ characters.
   - **Evidence Captured**: `query_name`, `entropy_score`, `query_length`, `query_type`, `destination_dns_server`.
   - **Potential Interpretation**: Covert DNS data exfiltration, C2 tunneling, or Algorithmically Generated Domains (DGA).
   - **False-Positive Considerations**: Content Delivery Networks (CDNs), anti-spam DNSBL lookups, cloud infrastructure telemetry.
   - **MITRE ATT&CK Association**: Potential association with `T1071.004: Application Layer Protocol: DNS`.

3. **RULE-006 — Cleartext HTTP Authentication Credentials**
   - **Observed Behavior**: HTTP payload transmitting cleartext authentication parameters (e.g. `user=`, `password=`, `pass=`) or HTTP Basic Auth over unencrypted transport.
   - **Evidence Captured**: `http_uri`, `http_method`, `destination_ip`, `destination_port`, `cleartext_field_matches`.
   - **Potential Interpretation**: Insecure credential transmission susceptible to network sniffing.
   - **False-Positive Considerations**: Legacy internal test utilities or deliberate honeypot test endpoints.
   - **MITRE ATT&CK Association**: Potential association with `T1040: Network Sniffing`.

---

## 6. Investigation Workflow (Analyst Walkthrough)

```text
Step 01: Ingest PCAP capture or select controlled test scenario.
Step 02: Verify SHA-256 fingerprint and file header magic bytes.
Step 03: Dissect multi-layer protocols (Ethernet through TLS).
Step 04: Reconstruct 5-tuple conversations and audit TCP handshake completion.
Step 05: Inspect DNS entropy, HTTP URIs/User-Agents, and TLS SNI records.
Step 06: Harvest and de-duplicate observable IOCs with packet index ranges.
Step 07: Evaluate 11 heuristic detection rules against environment profiles.
Step 08: Validate finding evidence, byte ratios, and ATT&CK context.
Step 09: Export structured JSON artifacts and 12-section technical investigation report.
```

---

## 7. Controlled Testing Lab (Synthetic PCAP Fixtures)

To validate detection logic without handling sensitive proprietary network data, test PCAPs are generated deterministically using Scapy (`tests/generate_test_pcaps.py`):

- `syn_port_scan.pcap` (45 packets): Rapid SYN attempts across ports 20–8080 on 10.10.20.5.
- `dns_tunneling_c2.pcap` (110 packets): Base64/hex-encoded high-entropy DNS queries over UDP 53.
- `cleartext_credentials.pcap` (68 packets): HTTP POST authentication to `/login.php` alongside non-standard port 4444 listener activity.
- `corporate_baseline.pcap` (250 packets): Benign browsing traffic to Google, Slack, and GitHub with clean TLS handshakes (0 alerts).

> **Operational Disclosure**: These captures are controlled laboratory test fixtures and do not represent real-world compromised infrastructure.

---

## 8. Security Hardening & Threat Controls

- **File Upload Protection**: Whitelist validation (`.pcap`, `.pcapng`), 50MB ceiling (`MAX_UPLOAD_SIZE_MB`, HTTP 413), and binary signature verification.
- **Path Traversal Defenses**: Analysis IDs strictly validated against `^[a-zA-Z0-9_-]{12,64}$`; rejection of `..` and path separators.
- **Subprocess Isolation**: All Python CLI executions use strict argument arrays (`shell=False`) with zero shell concatenation.
- **Resource Protection**: 60s hard timeout guard per analysis and concurrency semaphore (`MAX_CONCURRENT_ANALYSES=2`, HTTP 429 when saturated).
- **Non-Root Containers**: Docker containers execute under dedicated non-root user `pcapuser` (UID `10001`) with `no-new-privileges:true`.
- **Ephemeral Retention**: Sandboxed directories older than `RETENTION_DAYS` (default: 7) are purged via `scripts/cleanup_data.py`.

---

## 9. Limitations & Operational Boundaries

1. **Encrypted Payload Invisibility**: Encrypted TLS application streams cannot be inspected without private session keys.
2. **Heuristic Alerts Are Not Proof**: Statistical anomaly detections provide circumstantial indicators that require human SOC analyst verification.
3. **Capture Boundary**: Analysis is strictly confined to observed packets; off-path or unmirrored communications cannot be assessed.
4. **Lack of IP Reputation Data**: The analyzer operates completely offline without querying live commercial threat intelligence feeds.
5. **Resource Consumption on Large Files**: Processing PCAP files > 500MB without indexing can cause elevated memory utilization.

---

## 10. Technical Interview Preparation

### 60-Second Elevator Pitch
> "I built the Automated Python PCAP Analyzer & Threat Parser, an offline network-forensics platform. It parses PCAP/PCAPNG captures, reconstructs bidirectional 5-tuple flows, extracts observable IOCs, and evaluates 11 deterministic heuristic detection rules across calibrated environment profiles. The backend uses Python with native C-struct unpacking and Scapy/PyShark fallbacks served via FastAPI, while the frontend provides a high-density SOC analyst console in React/TypeScript. To ensure security and reliability, I implemented path-traversal defenses, non-root Docker execution, 44 automated unit tests, and reproducible synthetic PCAP fixtures."

### Technical Q&A Highlights
- **Why use both a native parser and Scapy/PyShark?**  
  *Native binary unpacking provides rapid Layer 2–4 dissection with zero external binary dependencies. Scapy and PyShark provide rich fallback capabilities when dissecting deep application-layer structures like complex DNS resource records or TLS extensions.*
- **How do you reconstruct conversation flows?**  
  *Packets are grouped by normalized 5-tuple `(min(src, dst), min(sport, dport), max(src, dst), max(sport, dport), protocol)`. The state machine inspects TCP flags in sequence to verify 3-way handshake completion (`SYN` -> `SYN-ACK` -> `ACK`), flag reset (`RST`) aborts, and track byte transfer ratios per direction.*
- **How are detections tested without real attacks?**  
  *Using Scapy, I wrote automated generator scripts that craft mathematically precise synthetic PCAPs reflecting specific traffic invariants (e.g. uncompleted SYN bursts, Shannon entropy spikes). These run in CI across 44 automated test cases to prevent regressions.*
