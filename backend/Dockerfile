# ==============================================================================
# Backend Dockerfile for Automated Python PCAP Analyzer
# ==============================================================================

FROM python:3.11-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    tshark \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 10001 pcapgroup && \
    useradd -u 10001 -g pcapgroup -s /bin/bash -m pcapuser

WORKDIR /app

COPY requirements.txt .
COPY pyproject.toml .

RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir uvicorn fastapi

COPY src/ /app/src/
COPY config/ /app/config/
COPY examples/ /app/examples/
COPY scripts/ /app/scripts/

RUN mkdir -p /app/data/analyses && \
    chown -R pcapuser:pcapgroup /app

USER 10001:10001

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    APP_ENV=production \
    API_HOST=0.0.0.0 \
    API_PORT=8000 \
    DATA_DIRECTORY=/app/data

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["python3", "-m", "uvicorn", "pcap_analyzer.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
