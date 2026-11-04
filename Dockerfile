# Hardened Dockerfile for Secure E-Commerce Admin & Refund Portal
FROM python:3.12-slim

# Prevent Python from writing bytecode and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install runtime and build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first for caching efficiency
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create an unprivileged user and group (appuser:appuser, uid 1000)
RUN groupadd -g 1000 appuser && \
    useradd -u 1000 -g appuser -s /bin/bash -m appuser

# Copy application source code
COPY . .

# Ensure data, logs, and evidence directories exist with proper permissions
RUN mkdir -p /app/data /app/logs /app/evidence && \
    chown -R appuser:appuser /app

# Switch to unprivileged user
USER appuser

EXPOSE 8000

# Container healthcheck querying the /health endpoint
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Launch: initialize/seed DB and start Uvicorn ASGI server
CMD ["sh", "-c", "python3 scripts/seed_db.py && uvicorn app.main:app --host 0.0.0.0 --port 8000"]

