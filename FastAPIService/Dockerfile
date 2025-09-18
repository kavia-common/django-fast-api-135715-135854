# syntax=docker/dockerfile:1.7
# Multi-stage build for smaller runtime image

FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    build-essential curl ca-certificates netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy application
COPY src /app/src

# Create non-root user
RUN useradd -m -u 10001 appuser
USER appuser

# Expose port
EXPOSE 8000

# Healthcheck (simple HTTP GET to /)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python - <<'PY' || exit 1
import sys, urllib.request
try:
    with urllib.request.urlopen("http://127.0.0.1:8000/") as r:
        sys.exit(0 if r.status == 200 else 1)
except Exception:
    sys.exit(1)
PY

# Start the FastAPI app
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
