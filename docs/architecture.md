# System Architecture

## Overview

The **Automated Python PCAP Analyzer & Threat Parser** is architected as a modular, layered defensive network forensics pipeline. It decouples low-level binary packet dissection from high-level flow state tracking, statistical aggregation, and heuristic threat detection.

```
                              +---------------------------+
                              |      Target Capture       |
                              |      (.pcap / .pcapng)    |
                              +-------------+-------------+
                                            |
                                            v
+---------------------------------------------------------------------------------------+
|                              LAYER 1: PACKET DISSECTION                                |
|                                                                                       |
|   +-----------------------+   +-----------------------+   +-----------------------+   |
|   |   NativePcapReader    |   |    ScapyPcapReader    |   |   PySharkPcapReader   |   |
|   |  (Zero dependencies,  |   |   (Scapy dissection,  |   | (Deep Wireshark/tshark|   |
|   |  RFC struct parsing)  |   |    when installed)    |   |  tree dissection)     |   |
|   +-----------+-----------+   +-----------+-----------+   +-----------+-----------+   |
+---------------|---------------------------|---------------------------|---------------+
                +---------------------------+---------------------------+
                                            |
                                            v (Stream of PacketRecord objects)
+---------------------------------------------------------------------------------------+
|                         LAYER 2: STATE & STATISTICS ENGINE                            |
|                                                                                       |
|  * Protocol Distribution Accounting (Layer 2, 3, 4, 7)                                |
|  * Flow / Conversation Tracking (IP:Port <-> IP:Port [Proto])                         |
|  * TCP State Machine Tracking (SYN, SYN-ACK, ACK, FIN, RST, Handshake Verification)  |
|  * Payload Extractions (DNS Queries, HTTP Headers, TLS SNI / Versions)                |
+-------------------------------------------+-------------------------------------------+
                                            |
                                            v (TrafficStatistics & FlowRecords)
+---------------------------------------------------------------------------------------+
|                         LAYER 3: THREAT DETECTION ENGINE                              |
|                                                                                       |
|  [RULE-001] TCP SYN Port Scanning Heuristic (Vertical & Horizontal Sweeps)           |
|  [RULE-002] Connection Flooding / Single Source Rate Surges                          |
|  [RULE-003] Unusual Destination Port Activity (Backdoors, RATs, C2)                   |
|  [RULE-004] DNS Query Volume Anomaly                                                  |
|  [RULE-005] Suspicious DNS Characteristics (Shannon Entropy & Tunneling Heuristics)   |
|  [RULE-006] Repeated Failed TCP Connection Handshakes                                 |
|  [RULE-007] ICMP Volume / Ping Sweep Anomaly                                          |
|  [RULE-008] Cleartext Protocol Observation (HTTP, FTP, Telnet Security Risk)          |
+-------------------------------------------+-------------------------------------------+
                                            |
                                            v (List of AlertFinding objects with evidence)
+---------------------------------------------------------------------------------------+
|                         LAYER 4: OUTPUT & REPORTING ENGINE                            |
|                                                                                       |
|  * JsonReporter: Machine-readable JSON output for SIEMs and pipeline automation       |
|  * TextReporter: 12-section formal SOC investigation report                           |
|  * CLI Presenter: Terminal summary table with colorized status and confidence scores  |
+---------------------------------------------------------------------------------------+
```

---

## Component Breakdown

### 1. Packet Ingestion & Parsing Layer (`pcap_analyzer.parser`)

The parser layer provides an abstract interface (`BasePcapReader`) with three distinct implementations:

- **`NativePcapReader`**: Written in pure Python using `struct`, `socket`, and `datetime`. It natively handles big-endian and little-endian libpcap formats (`0xA1B2C3D4`, `0xD4C3B2A1`, `0xA1B23C4D`, `0x4D3CB2A1`) as well as PCAPNG Section Header Blocks and Enhanced Packet Blocks. It operates with **zero external dependencies**, allowing execution in minimal environments or air-gapped systems.
- **`ScapyPcapReader`**: Uses Scapy's `rdpcap` and `PcapReader` for full Python-based packet manipulation when Scapy is installed.
- **`PySharkPcapReader`**: Wraps Wireshark's `tshark` binary via PyShark for edge cases requiring deep proprietary or specialized protocol dissectors.
- **Resilient Error Containment**: Individual malformed or truncated packets are recorded in `parsing_errors` without aborting the capture parsing stream.

### 2. Protocol Dissection Subsystem (`pcap_analyzer.protocols`)

Handles binary extraction across network layers:
- **Layer 2 (Data Link)**: Ethernet II, 802.1Q VLAN tag unwrapping, ARP.
- **Layer 3 (Network)**: IPv4 header options, IPv6 next-header chains, ICMP echo/unreachable typing.
- **Layer 4 (Transport)**: TCP sequence numbers, acknowledgment numbers, flags bitmap (SYN, ACK, FIN, RST, PSH, URG), UDP datagram framing.
- **Layer 7 (Application)**:
  - **DNS**: Transaction ID, flags, QNAME decompression pointer traversal (`0xC0`), QTYPE (A, AAAA, CNAME, TXT, MX), answer records.
  - **HTTP**: Request method extraction (GET, POST, PUT, DELETE, HEAD), URI path, `Host` header, `User-Agent`, response status codes.
  - **TLS**: Record layer content types (Handshake, Application Data), version negotiation (TLS 1.0 - 1.3), ClientHello handshake dissection, and Server Name Indication (SNI extension `0x0000`) extraction.

### 3. Statistics & Flow Engine (`pcap_analyzer.statistics`)

Tracks bidirectional and unidirectional conversations:
- Maintains endpoints, byte counts, and packet counters.
- Reconstructs TCP handshake states (`SYN` -> `SYN-ACK` -> `ACK`) to determine whether a connection successfully reached an `ESTABLISHED` state or was abandoned/reset.
- Computes bandwidth metrics, duration, average packet sizes, and top endpoint talkers.

### 4. Heuristic Threat Detection Engine (`pcap_analyzer.detections`)

Implements a pluggable, rule-based architecture (`BaseDetectionRule`).
- Rules are evaluated against parsed packets, conversation flows, and aggregate statistics.
- Every triggered rule generates an `AlertFinding` object populated with **concrete numerical evidence** (e.g. unique destination ports, completion ratio, sample queries).
- Thresholds are defined in `AnalysisConfig` (`pcap_analyzer.config`) rather than hardcoded in rule logic.

### 5. Reporting Layer (`pcap_analyzer.reporting`)

- **JSON Reporter**: Exports an immutable JSON document structure for ingestion into SIEMs, Splunk, Elastic, or automated test pipelines.
- **Text Reporter**: Renders a standardized, 12-section technical investigation report adhering to standard incident response documentation guidelines.
