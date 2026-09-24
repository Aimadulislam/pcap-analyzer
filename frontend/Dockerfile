# ==============================================================================
# Multi-Stage Frontend Dockerfile for PCAP Threat Analyzer
# Stage 1: Build with Node 20 Alpine
# Stage 2: Serve with minimal unprivileged Nginx web server
# ==============================================================================

# --- Stage 1: Build ---
FROM node:20-alpine AS builder

WORKDIR /app

# Copy dependency locks and manifests
COPY package.json package-lock.json* ./

# Clean install with reproducible npm ci
RUN npm ci

# Copy source assets
COPY tsconfig.json vite.config.ts index.html ./
COPY src/ ./src/
COPY public/ ./public/

# Compile production bundle
RUN npm run build

# --- Stage 2: Serve ---
FROM nginxinc/nginx-unprivileged:alpine AS runner

# Copy compiled assets from builder
COPY --from=builder /app/dist /usr/share/nginx/html

# Expose standard unprivileged web port
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD wget -q -O /dev/null http://localhost:8080/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
