# System Architecture

## Conceptual Pipeline

The **Automated Python PCAP Analyzer & Threat Parser** is architected around a clean, decoupled dataflow model that transforms raw capture binaries into actionable security intelligence and formal investigation reports:

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

---

## Architectural Stages

### 1. Ingestion & Dissection: Packet Parser (`pcap_analyzer.parser`)

The ingestion stage ingests raw packet captures in standard libpcap or modern PCAPNG formats. The parser layer provides an abstract interface (`BasePcapReader`) with three distinct implementations:

- **`NativePcapReader`**: Pure Python implementation using `struct`, `socket`, and `datetime`. It natively unpacks libpcap headers (magic numbers `0xA1B2C3D4`, `0xD4C3B2A1`, `0xA1B23C4D`, `0x4D3CB2A1`) and PCAPNG Section Header / Enhanced Packet Blocks with **zero external dependencies**.
- **`ScapyPcapReader`**: Leverages Scapy's dissection engine when installed in the environment.
- **`PySharkPcapReader`**: Interfaces with Wireshark/tshark dissectors for specialized or proprietary protocols.
- **Resilient Stream**: Per-packet parsing errors are logged in `parsing_errors` without terminating the capture analysis stream.

The parser produces a continuous stream of structured `PacketRecord` objects.

---

### 2. Tripartite Processing Subsystems

The parsed packet stream branches into three specialized analytical subsystems:

#### A. Protocols (`DNS`, `HTTP`, `TLS`)
- **`DNSAnalyzer` (`pcap_analyzer.dns_analyzer`)**: Dissects DNS queries and responses, transactions IDs, record types (A, AAAA, CNAME, TXT, MX, NS, PTR), response codes (NOERROR, NXDOMAIN, SERVFAIL), returned IP answers, and computes per-label Shannon entropy.
- **`HTTPAnalyzer` (`pcap_analyzer.http_analyzer`)**: Dissects cleartext HTTP transactions, extracting request methods (GET, POST, PUT, DELETE, HEAD, OPTIONS), Host headers, URI paths, User-Agent strings, response status codes, and MIME content types.
- **`TLSAnalyzer` (`pcap_analyzer.tls_analyzer`)**: Inspects unencrypted TLS record layer metadata, ClientHello handshakes, TLS versions (SSL 3.0, TLS 1.0, 1.1, 1.2, 1.3), Server Name Indication (SNI) extensions, and cipher suite references without attempting decryption.

#### B. Flows (`TCP / UDP`)
- **`StatisticsEngine` (`pcap_analyzer.statistics`)**: Reconstructs bidirectional conversations (`src_ip:port <-> dst_ip:port [proto]`).
- Tracks TCP 3-way handshake state machine (`SYN` → `SYN-ACK` → `ACK`), reset flags (`RST`), teardown (`FIN`), and calculates metrics including Packets Per Second (PPS), Bytes Per Second (BPS), and duration.
- Classifies flows into observable states: normal TCP session, incomplete TCP connection, repeated connection attempts, UDP communication, and ICMP communication.

#### C. Metadata (`IOCs`, `Integrity`)
- **`IOCExtractor` (`pcap_analyzer.iocs`)**: Identifies, extracts, and deduplicates observable network indicators (IPv4, IPv6, domain names, hostnames, URLs, email addresses, checksums). Tracks first-seen/last-seen timestamps and packet references.
- **Forensic Integrity Manifest**: Computes cryptographic SHA-256 digests of the capture binary to establish strict chain-of-custody, capture duration, and packet boundary bounds.

---

### 3. Detection Engine (`pcap_analyzer.detections`)

The Detection Engine ingests the structured protocol intelligence (DNS, HTTP, TLS) and conversation flows (TCP/UDP) alongside baseline statistics. It evaluates a modular suite of deterministic, evidence-based heuristic rules (`RULE-001` through `RULE-011`).

Every triggered detection generates a tripartite output:
1. **Findings**: Structured title, category, rule ID, affected source and destination endpoints, and plain-language descriptions.
2. **Evidence**: Concrete numerical observables, sample queries/URLs/ports, entropy scores, and exact packet number references.
3. **Severity & Confidence**: Calibrated severity classification (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) paired with a fractional confidence score ($0.0 - 1.0$), recommended next steps, and forensic limitations.

---

### 4. Presentation & Artifact Export (`pcap_analyzer.reporting`)

The compiled analysis result is emitted through multiple reporting channels:
- **SIEM-Ready JSON (`JsonReporter`)**: Comprehensive, machine-readable JSON schema for automated ingestion into Splunk, Elastic SIEM, and SOC data lakes.
- **12-Section Formal Investigation Report (`TextReporter`)**: Structured forensic incident response document containing executive summaries, forensic integrity hashes, protocol distributions, top talkers, security findings with full evidence, and IOC manifests.
- **IOC Artifacts (`--iocs`)**: Standalone JSON/CSV file containing all extracted, deduplicated network indicators.
- **Interactive CLI**: Colorized terminal summary displaying high-priority alerts, protocol distributions, and analysis metrics.
