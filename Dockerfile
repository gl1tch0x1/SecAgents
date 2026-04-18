# Multi-stage Dockerfile for SecAgents
# Build stage
FROM python:3.11-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -e .

# Runtime stage
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    iputils-ping \
    dnsutils \
    netcat-openbsd \
    grep \
    coreutils \
    && rm -rf /var/lib/apt/lists/*

# Copy Python environment from builder
COPY --from=builder /usr/local /usr/local

# Create non-root user for security
RUN useradd -m -u 1000 secagents && \
    mkdir -p /app /scans /reports && \
    chown -R secagents:secagents /app /scans /reports

USER secagents

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:11434/api/tags 2>/dev/null || echo "unhealthy"

# Default environment
ENV SECAGENTS_PROVIDER=ollama \
    SECAGENTS_OLLAMA_BASE_URL=http://ollama:11434 \
    PYTHONUNBUFFERED=1

# Volumes for scans and reports
VOLUME ["/scans", "/reports"]

# Entry point
ENTRYPOINT ["secagents"]
CMD ["--help"]
