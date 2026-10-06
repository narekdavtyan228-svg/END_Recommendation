# syntax=docker/dockerfile:1
# Build stage: dependencies are installed from the hashed lock file, wheels only (no compiler
# is needed, and the build stage is not part of the runtime image).
FROM python:3.12-slim AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /build
COPY requirements.lock .
RUN python -m venv /opt/venv && /opt/venv/bin/pip install --require-hashes --only-binary=:all: -r requirements.lock

# Runtime stage: non-root user, nothing writable except /tmp (a tmpfs in compose).
FROM python:3.12-slim AS runtime
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PATH=/opt/venv/bin:$PATH PYTHONPATH=/app
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin aicheck
COPY --from=build /opt/venv /opt/venv
WORKDIR /app
COPY aicheck ./aicheck
COPY openapi.json ./
USER 10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/v1/health', timeout=2).status == 200 else 1)"]
CMD ["uvicorn", "--factory", "aicheck.api.server:build", "--host", "0.0.0.0", "--port", "8000"]

# Development stand-in for the local model (docker compose only).
FROM runtime AS fake-llm
COPY tests/fakes/fake_llm.py /app/fake_llm.py
CMD ["python", "/app/fake_llm.py"]
