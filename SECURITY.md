# Security Policy & Defensive Threat Model

## Supported Versions

| Version | Supported | Security Review Status |
| :--- | :--- | :--- |
| `0.1.x` | :white_check_mark: Active | Current Development Baseline |
| `< 0.1.0` | :x: Deprecated | Alpha / Experimental Stages |

---

## Defensive Architecture & Threat Model

The **Automated Python PCAP Analyzer & Threat Parser** processes untrusted binary packet captures. Untrusted input parsing is inherently high-risk; consequently, this application incorporates strict defense-in-depth principles:

### 1. File Upload & Ingestion Security
- **Strict Extension Whitelisting**: Only `.pcap` and `.pcapng` files are accepted. All other extensions are rejected immediately with HTTP 400.
- **Payload Size Enforcement**: Enforces a strict maximum upload limit (default: 50MB, configurable via `MAX_UPLOAD_SIZE_MB`). Uploads exceeding this threshold receive HTTP 413 Payload Too Large before processing.
- **Server-Side ID Isolation**: User-supplied filenames are never used as filesystem paths or storage names. Every analysis run receives an ephemeral, cryptographically random ID (`analysis_<timestamp>_<uuid4_hex>`).
- **Path Traversal Protection**: All paths are validated with strict regex patterns (`^[a-zA-Z0-9_-]{12,64}$`). Any presence of `..`, `/`, or `\` triggers a `StorageSecurityError`.

### 2. Subprocess & Parsing Execution Security
- **Argument Array Execution**: All process invocations (`python3 -m src.pcap_analyzer.cli`) utilize strict argument arrays (`execFile` / `subprocess.run(args, shell=False)`). Shell interpolation (`shell=True`) is strictly prohibited throughout the entire codebase.
- **Execution Timeouts**: Every analysis invocation is wrapped in an explicit timeout guard (`ANALYSIS_TIMEOUT_SECONDS`, default: 60s) to prevent CPU starvation and DoS from maliciously crafted packet captures.
- **Concurrency Limiting**: Active concurrent analyses are restricted to a configurable pool (`MAX_CONCURRENT_ANALYSES`, default: 2) to protect host memory and prevent thread exhaustion.

### 3. Container & Operating System Hardening
- **Non-Root Execution**: Containerized environments run strictly under an unprivileged non-root user (`pcapuser`, UID 10001).
- **Read-Only / Sandboxed Storage**: Storage is isolated to `./data/analyses/<analysis_id>/` with restricted directory permissions.
- **Automated Retention**: Ephemeral forensic files and temporary uploads are automatically purged after the retention window (`RETENTION_DAYS`, default: 7).

### 4. Network & HTTP Controls
- **Explicit CORS**: Wildcard origins (`*`) are disallowed in production environments. Explicit origin lists must be configured via `CORS_ORIGINS`.
- **Security Headers**: Standard defense-in-depth headers are attached to all API responses:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: SAMEORIGIN`
  - `Referrer-Policy: strict-origin-when-cross-origin`
- **Request Tracking**: Every request receives a unique `X-Request-ID` header for end-to-end audit logging.

---

## Public Portfolio vs. Local Forensic Execution

| Environment | Purpose | Upload Policy | Data Boundary |
| :--- | :--- | :--- | :--- |
| **Public Portfolio Demo** | Demonstration & evaluation | **Disabled / Synthetic Only** | Pre-generated, sanitized synthetic captures containing zero real network telemetry. |
| **Local / Private Deployment** | Real incident investigation | **Enabled (Protected)** | Runs locally in Docker or air-gapped host behind private authentication. |

> **Warning**: Never expose an unauthenticated public PCAP analysis service to the open internet. PCAP captures may contain unencrypted passwords, API tokens, internal IP ranges, and confidential network topology details.

---

## Reporting a Vulnerability

If you discover a security vulnerability or bypass in the parsing engine, API handlers, or container configurations:

1. **Do not create a public GitHub issue.**
2. Submit your findings via GitHub Security Advisories or email the engineering team.
3. Include:
   - Description of the vulnerability
   - Proof-of-concept capture or request payload
   - Impact assessment
4. Security advisories are acknowledged within 48 hours, with patches prioritized according to severity.
