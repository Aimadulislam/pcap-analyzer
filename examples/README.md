# Synthetic PCAP Scenarios & Lab Captures

This directory provides pre-generated synthetic packet captures (`.pcap`) and generator scripts to evaluate and test the **Automated Python PCAP Analyzer & Threat Parser** without needing root packet-capture privileges or live attack tools.

## Included PCAP Scenarios

| Capture File | Description | Triggered Detections | Packets |
| :--- | :--- | :--- | :--- |
| `syn_port_scan.pcap` | Host `192.168.4.88` executing an automated vertical TCP SYN scan across 45 target ports on server `10.10.20.5`. | `RULE-001` (TCP SYN Scan, HIGH)<br>`RULE-006` (Failed Connections, MEDIUM)<br>`RULE-008` (Cleartext Observation, LOW) | 50 |
| `dns_tunneling_c2.pcap` | Host `10.0.5.120` exfiltrating base64/hex data chunks disguised as subdomains to `tunnel.stealth-c2-domain.org`. | `RULE-005` (Suspicious DNS Characteristics, HIGH)<br>`RULE-004` (DNS Query Volume Anomaly, MEDIUM) | 110 |
| `cleartext_credentials.pcap` | Unencrypted HTTP GET login transaction on port 80 alongside backdoor traffic targeting unusual port 4444 (Metasploit default listener). | `RULE-003` (Unusual Destination Port 4444, LOW)<br>`RULE-008` (Cleartext HTTP, LOW) | 7 |
| `corporate_baseline.pcap` | Benign internal network traffic with normal TLS 1.2 handshakes (SNI: `api.github.com`), standard DNS resolution, and gateway ICMP ping/echo. | **0 Alerts** (Clean baseline verification) | 10 |

---

## Regenerating PCAP Files

To re-synthesize or customize the sample captures:

```bash
python3 examples/generate_sample_pcap.py
```

All packets are assembled byte-by-byte using standard RFC framing (Ethernet II, IPv4, TCP/UDP/ICMP, DNS, HTTP, TLS) in Python's standard `struct` library.

---

## Running Analysis via CLI

Analyze any capture directly:

```bash
# Analyze SYN scan capture with human-readable report:
python3 -m pcap_analyzer -i examples/syn_port_scan.pcap -r sample_reports/syn_port_scan_report.txt

# Analyze DNS exfiltration with JSON output:
python3 -m pcap_analyzer -i examples/dns_tunneling_c2.pcap -o sample_reports/dns_tunneling.json

# Analyze with custom detection threshold overrides:
python3 -m pcap_analyzer -i examples/cleartext_credentials.pcap -v
```
