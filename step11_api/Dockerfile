# SBOM POC Tool API — Dockerfile
# Session: SBOM-20260409-sb01
# Generated: Step 11 — FastAPI API Generation
#
# Build:  docker build -t sbom-poc-api .
# Run:    docker run --rm -p 8000:8000 --env-file .env sbom-poc-api
#
# The step6 and step9 source files live in the session root (one level above
# step11_api/).  The COPY instructions below bring them into the image so that
# the sys.path injection in dependencies.py resolves them at runtime.

FROM python:3.11-slim

# Security: run as non-root
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

WORKDIR /app

# Copy dependency manifest first to exploit Docker layer cache
COPY step11_api/requirements.txt ./requirements.txt

RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

# Copy session-root Python modules that the API imports at runtime
COPY step6_tdd_green_phase.py .
COPY step7_5_pydantic_models.py .
COPY step9_tdd_green_phase_orchestration.py .

# Copy the API package
COPY step11_api/ ./step11_api/

# Optional: copy .env if present (override via docker run --env-file for secrets)
# COPY step11_api/.env .env

# Drop to non-root
RUN chown -R appuser:appgroup /app
USER appuser

# Expose API port (override via PORT env var + uvicorn --port)
EXPOSE 8000

# Health check — uses the /api/v1/health endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health')" || exit 1

# Entry point — run as a module so relative imports work correctly
CMD ["python", "-m", "uvicorn", "step11_api.main:app", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--no-access-log"]
