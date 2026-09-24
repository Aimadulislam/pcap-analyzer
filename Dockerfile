# ==============================================================================
# Production Dockerfile for Automated Python PCAP Analyzer & Threat Parser
# Multi-stage, minimal attack surface, non-root user execution.
# ==============================================================================

FROM python:3.11-slim AS base

# Install minimal OS dependencies: libpcap for native packet reads, tshark for PyShark
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    tshark \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated non-root application user and group
RUN groupadd -g 10001 pcapgroup && \
    useradd -u 10001 -g pcapgroup -s /bin/bash -m pcapuser

# Set working directory
WORKDIR /app

# Copy dependency specifications
COPY requirements.txt .
COPY pyproject.toml .

# Install Python production dependencies
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir uvicorn fastapi

# Copy application source code and configuration profiles
COPY src/ /app/src/
COPY config/ /app/config/
COPY examples/ /app/examples/
COPY scripts/ /app/scripts/

# Create data directory and assign ownership to non-root user
RUN mkdir -p /app/data/analyses && \
    chown -R pcapuser:pcapgroup /app

# Switch to non-root user
USER 10001:10001

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    APP_ENV=production \
    API_HOST=0.0.0.0 \
    API_PORT=8000 \
    DATA_DIRECTORY=/app/data

# Expose API port
EXPOSE 8000

# Docker Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Launch ASGI production server with uvicorn
CMD ["python3", "-m", "uvicorn", "pcap_analyzer.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
