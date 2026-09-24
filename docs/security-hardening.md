# Security Hardening & Threat Mitigation

This document details the concrete security controls and defensive mitigations implemented in the **Automated Python PCAP Analyzer & Threat Parser**.

---

## Threat Matrix & Implemented Mitigations

| Threat Vector | Risk Description | Implemented Defensive Control | Code Reference |
| :--- | :--- | :--- | :--- |
| **Path Traversal** | Adversary uploads filenames with `../` or `/` attempting to overwrite system files. | Whitelist regex `^[a-zA-Z0-9_-]{12,64}$`, canonical path verification, rejection of path separators. | `src/pcap_analyzer/storage/manager.py` |
| **Arbitrary Code Execution** | Malicious capture craft to trigger shell execution during dissection. | Subprocess invocations use strict argument lists with `shell=False`. No user input is concatenated into shell strings. | `server.ts`, `cli.py` |
| **Denial of Service (Memory)** | Huge PCAP file causes out-of-memory (OOM) crash. | Maximum upload size enforcement (`MAX_UPLOAD_SIZE_MB=50`, HTTP 413 Payload Too Large) checked before analysis. | `server.ts`, `settings.py` |
| **Denial of Service (CPU)** | Complex malformed PCAP triggers infinite parsing loops or regex catastrophic backtracking. | Strict execution timeout (`ANALYSIS_TIMEOUT_SECONDS=60`). Process terminates gracefully if limit is reached. | `server.ts`, `app.py` |
| **Resource Starvation** | Multiple simultaneous upload requests overwhelm host thread pool. | Configurable concurrency semaphore (`MAX_CONCURRENT_ANALYSES=2`). Returns HTTP 429 when saturated. | `server.ts`, `settings.py` |
| **Privilege Escalation** | Compromise of parser provides root host control. | Docker containers execute under unprivileged non-root user (`pcapuser`, UID `10001`). Container security option `no-new-privileges:true`. | `Dockerfile`, `docker-compose.prod.yml` |
| **Cross-Origin Exposure** | Unauthorized third-party web apps querying internal capture data. | Strict CORS origin verification via `CORS_ORIGINS`. Wildcard `*` rejected in production. | `server.ts`, `app.py` |
| **Data Leakage (Residual Files)** | Temporary analysis directories accumulate on disk indefinitely. | Scheduled data retention cleanup via `scripts/cleanup_data.py`, removing records older than `RETENTION_DAYS`. | `scripts/cleanup_data.py` |
| **Sensitive Log Leakage** | Raw packet payloads or credentials recorded to log files. | Structured logging outputs event metadata, request IDs, and timings only. Payload contents are excluded from logs. | `server.ts`, `routes.py` |

---

## Network Security Headers

The backend API attaches standard defense-in-depth HTTP security headers to every response:

```http
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin
Content-Security-Policy: default-src 'self'; frame-ancestors 'self';
```

---

## File Ingestion & Sandbox Workflow

```
1. Receive multipart upload stream
           │
           ▼
2. Validate extension against whitelist (.pcap, .pcapng)
           │
           ▼
3. Enforce payload size limit (<= 50MB) -> Reject 413 if exceeded
           │
           ▼
4. Generate server-side random ID (analysis_<timestamp>_<uuid>)
           │
           ▼
5. Write bytes to sandboxed directory: data/analyses/<analysis_id>/capture.pcap
           │
           ▼
6. Compute SHA-256 cryptographic fingerprint
           │
           ▼
7. Execute Python dissection with concurrency lock & 60s timeout
           │
           ▼
8. Write structured output artifacts (results.json, report.txt, iocs.json)
           │
           ▼
9. Clean up ephemeral stream buffers & release concurrency lock
```
