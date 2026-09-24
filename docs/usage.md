# Usage Guide

## Installation

### Prerequisites
- Python 3.10, 3.11, or 3.12
- Git

### 1. Clone Repository & Setup Virtual Environment
```bash
git clone https://github.com/username/pcap-threat-analyzer.git
cd pcap-threat-analyzer

python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

### 2. Install Dependencies

#### Core Installation (Zero External Libraries Required)
The analyzer includes a built-in `NativePcapReader` using standard library `struct` and `socket`. You can run the analyzer immediately without installing third-party packages!

#### Full Feature Installation (Scapy & Testing Tools)
```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

#### Wireshark / tshark Setup (Optional, for PyShark Engine)
If you wish to use the `--engine pyshark` dissector:
- **Ubuntu/Debian**: `sudo apt install -y tshark`
- **macOS**: `brew install wireshark`
- **Windows**: Install Wireshark and add the directory containing `tshark.exe` to your `PATH`.

---

## Command-Line Interface (CLI)

The package can be executed directly as a module:

```bash
python3 -m pcap_analyzer [OPTIONS] [PCAP_FILE]
```

### Common CLI Commands

#### 1. Basic Analysis & Terminal Overview
```bash
python3 -m pcap_analyzer capture.pcap
```

#### 2. Export Structured JSON Output
```bash
python3 -m pcap_analyzer -i capture.pcap -o analysis.json
```

#### 3. Generate 12-Section Investigation Report
```bash
python3 -m pcap_analyzer -i capture.pcap -r forensic_report.txt
```

#### 4. Combined Execution with Both Output Formats
```bash
python3 -m pcap_analyzer -i capture.pcap -o analysis.json -r forensic_report.txt
```

#### 5. Restrict Packet Processing (Large PCAP Triage)
To quickly triage a multi-gigabyte capture file without loading all packets:
```bash
python3 -m pcap_analyzer -i large_capture.pcap --max-packets 10000 -r triage_report.txt
```

#### 6. Custom Detection Thresholds Configuration
```bash
python3 -m pcap_analyzer -i capture.pcap -c custom_thresholds.json -v
```

---

## Custom Configuration JSON Schema

Create a JSON file (e.g. `custom_thresholds.json`) to adjust sensitivity:

```json
{
  "detection": {
    "syn_scan_unique_port_threshold": 15,
    "syn_scan_unique_host_threshold": 10,
    "syn_scan_min_packets": 20,
    "syn_scan_completion_ratio_max": 0.20,
    "connection_flood_rate_threshold": 60.0,
    "connection_flood_min_packets": 100,
    "unusual_ports": [1337, 31337, 4444, 5555, 6667, 8888, 9999],
    "dns_query_volume_threshold": 80,
    "dns_query_rate_threshold": 15.0,
    "dns_suspicious_length_threshold": 45,
    "dns_high_entropy_threshold": 3.75,
    "failed_connection_threshold": 20,
    "icmp_volume_threshold": 50,
    "cleartext_protocols": ["HTTP", "FTP", "TELNET"]
  },
  "max_packets_to_parse": null,
  "preferred_engine": "auto",
  "verbose_logging": false
}
```

---

## Programmatic Python API

The analyzer is designed for clean integration into custom SIEM automation scripts, Jupyter notebooks, or security pipelines:

```python
from pathlib import Path
from pcap_analyzer import PCAPAnalyzer, AnalysisConfig

# 1. Initialize analyzer
config = AnalysisConfig()
config.detection.syn_scan_unique_port_threshold = 20

analyzer = PCAPAnalyzer("examples/syn_port_scan.pcap", config=config)

# 2. Execute analysis
result = analyzer.analyze()

# 3. Access structured properties
print(f"Total Packets: {result.summary.total_packets}")
print(f"Unique Sources: {result.summary.unique_source_ips}")

for finding in result.findings:
    print(f"[{finding.severity}] {finding.title}")
    print(f"  Confidence: {finding.confidence}")
    print(f"  Evidence: {finding.evidence}")

# 4. Export artifacts
analyzer.export_json("output.json")
analyzer.export_report("report.txt")
```

---

## Running the Automated Test Suite

```bash
# Using pytest (when installed):
pytest -v

# Using Python standard library unittest:
python3 -m unittest discover -s tests -p "test_*.py" -v
```
