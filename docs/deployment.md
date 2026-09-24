# Deployment Guide & Architecture Strategies

This document provides deployment guidelines for running the **Automated Python PCAP Analyzer & Threat Parser** in development, local forensic, and production environments.

---

## Architecture Overview

```
                      Internet / Client
                             │
                             ▼
                    HTTPS Reverse Proxy
                 (Nginx / Traefik / Caddy)
                             │
            ┌────────────────┴────────────────┐
            ▼                                 ▼
   Frontend Service (8080)           Backend API (8000)
    (Nginx Alpine Static)             (FastAPI / Uvicorn)
                                              │
                                              ▼
                                      Analysis Sandbox
                                    (data/analyses/<id>/)
                                              │
                                      Python Analyzer
                                    (Native / Libpcap)
```

---

## Deployment Modes

### Option A: Local Forensic Deployment (Recommended for Investigations)

Best suited for SOC analysts, threat hunters, and incident responders examining real packet captures containing sensitive network data.

#### Using Docker Compose (Quickest)

```bash
# 1. Clone repository
git clone <YOUR_REPOSITORY_URL>
cd pcap-threat-analyzer

# 2. Configure environment
cp .env.example .env

# 3. Launch local Docker stack
docker compose up --build
```

Access:
- **Analyst Workspace**: `http://localhost:3000`
- **Backend API & Swagger**: `http://localhost:8000/docs`
- **Health Probe**: `http://localhost:8000/health`

#### Non-Docker Local Installation

```bash
# 1. Create and activate Python virtual environment
python3 -m venv venv
source venv/bin/activate

# 2. Install backend dependencies
pip install -r requirements.txt

# 3. Start backend API
PYTHONPATH=src python3 -m src.pcap_analyzer.api.app

# 4. In a separate terminal, start frontend
npm ci
npm run dev
```

---

### Option B: Public Portfolio Demo (Synthetic Showcase)

When deploying this project to a public portfolio site or cloud preview:

1. **Disable Public File Uploads by Default**: Do not accept untrusted PCAP uploads from anonymous internet users without authentication and rate-limiting.
2. **Enable Demo Mode**: The application provides an isolated Demo Mode with 4 pre-packaged synthetic scenarios (`syn_port_scan`, `dns_tunneling`, `cleartext`, `corporate_baseline`).
3. **Data Boundary**: Demo data is completely synthetic, created using Scapy (`tests/generate_test_pcaps.py`), and contains zero confidential network telemetry.

---

## Production Security Checklist

- [ ] **HTTPS Enforced**: Terminate TLS at the reverse proxy; do not expose HTTP to untrusted networks.
- [ ] **Non-Root Containers**: Ensure containers execute under UID `10001` (`pcapuser`).
- [ ] **CORS Restricted**: Set `CORS_ORIGINS` to the exact domain of your frontend.
- [ ] **Resource Limits**: Enforce CPU and memory limits in `docker-compose.prod.yml`.
- [ ] **Retention Automated**: Schedule `scripts/cleanup_data.py --execute` as a daily cron job to prevent disk exhaustion.
