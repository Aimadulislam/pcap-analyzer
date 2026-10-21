# Threat Model & Security Architecture

## 1. System Overview & Asset Inventory

The **Automated Python PCAP Analyzer & Threat Parser** ingests, processes, and visualizes network packet captures (`.pcap` / `.pcapng`). Network packet data is inherently untrusted binary input and may contain sensitive operational telemetry, cleartext passwords, internal addressing schemes, or adversarial exploit attempts.

### Protected Assets
| Asset | Classification | Description |
| :--- | :--- | :--- |
| **Uploaded PCAP Files** | Confidential | Raw network capture binaries stored temporarily during dissection. |
| **Analysis Artifacts** | Confidential | Structured JSON results, extracted IOC manifests, and 12-section plaintext reports. |
| **Extracted Network Metadata** | Confidential | Dissected DNS queries, HTTP User-Agents/URIs, TLS SNIs, and conversation flows. |
| **Host System & Runtime** | Critical | Server OS filesystem, container environment, and underlying execution resources. |
| **Application Configuration** | Internal | Environment variables, detection profiles, and CORS configuration. |

---

## 2. Threat Analysis & Mitigations

### Threat 1: Maliciously Crafted Binary PCAP / Exploit Payloads
- **Risk**: An attacker uploads a corrupted or malformed capture designed to exploit memory corruption vulnerabilities in libpcap, native parsers, or Wireshark dissectors.
- **Controls Implemented**:
  - Pure-Python struct unpacking with bounded memory reads (`NativePcapReader`).
  - Resilient exception handlers wrap per-packet frame parsing; malformed packets are appended to `parsing_errors` without terminating the process.
  - Multi-stage Docker containers run unprivileged (`pcapuser`, UID `10001`) with `no-new-privileges:true`.

### Threat 2: Path Traversal & Arbitrary File Overwrite
- **Risk**: File upload filenames or analysis IDs containing directory traversal sequences (e.g. `../../etc/passwd` or `..\windows\system32`) attempt to escape storage sandboxes.
- **Controls Implemented**:
  - Filenames are sanitized via `pathlib.Path.name` / `path.basename()`.
  - Analysis IDs are validated strictly against regex `^[a-zA-Z0-9_-]{12,64}$`.
  - Canonical sandbox paths (`data/analyses/<id>/`) are resolved and verified to prevent boundary escape (`StorageSecurityError`).

### Threat 3: Command & Argument Injection
- **Risk**: User-supplied parameters (filenames, profiles, engines) passed into CLI subcommands attempt to break out into host shell commands.
- **Controls Implemented**:
  - Subprocess execution uses strict argument arrays (`execFile` / `subprocess.run(args, shell=False)`).
  - Absolute paths are used; no user-controlled strings are evaluated inside a system shell.
  - Profile and engine inputs are validated against fixed enums (`default`, `home_lab`, `enterprise`, `high_volume`).

### Threat 4: Denial of Service & Resource Exhaustion (DoS)
- **Risk**: Massive PCAP files (e.g. multi-gigabyte captures) or concurrent upload floods exhaust CPU, memory, and disk space.
- **Controls Implemented**:
  - Strict upload ceiling of 50MB (`MAX_UPLOAD_SIZE_MB`); requests exceeding this limit receive `HTTP 413 Payload Too Large`.
  - Hard execution timeout guard of 60 seconds (`ANALYSIS_TIMEOUT_SECONDS`); long-running processes are terminated safely.
  - Concurrency semaphore (`MAX_CONCURRENT_ANALYSES=2`); requests exceeding capacity receive `HTTP 429 Too Many Requests`.

### Threat 5: Data Retention & Sensitive Telemetry Accumulation
- **Risk**: Sensitive PCAP captures and incident reports accumulate on server disk indefinitely, increasing exposure surface.
- **Controls Implemented**:
  - Automated ephemeral retention cleanup utility (`scripts/cleanup_data.py`).
  - Sandboxed folders older than `RETENTION_DAYS` (default: 7 days) are purged automatically.
  - Active analyses (`processing`, `queued`) are protected from premature deletion.

### Threat 6: Dependency Vulnerabilities & Supply Chain Compromise
- **Risk**: Third-party Python or Node packages introduce vulnerabilities into the analysis runtime.
- **Controls Implemented**:
  - Minimal dependency footprint (zero mandatory C-extensions for the native engine).
  - Automated dependency auditing via `pip-audit`, `npm audit`, and GitHub Dependabot.
  - Gitleaks secret scanning configured in CI to prevent credential leakage.

---

## 3. Operational Boundaries & Residual Risks

1. **Encrypted Payload Invisibility**: TLS application data is encrypted; the platform analyzes only unencrypted handshake metadata (SNI, cipher suites, TLS version).
2. **Offline Detection Boundary**: The analyzer operates strictly offline and does not query live external threat intelligence or reputation feeds.
3. **Heuristic Finding Context**: Detections reflect statistical and behavioral patterns. Analyst contextual verification is required to differentiate authorized scanner traffic from malicious reconnaissance.
4. **Local Execution Recommendation**: For active corporate incident triage, execute the analyzer locally or on isolated forensic workstations rather than exposing unauthenticated analysis endpoints to the public internet.
