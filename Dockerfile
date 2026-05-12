# EXPOSE Core — multi-stage container build.
#
# Per ADR-003: multi-arch (x86_64 + arm64) via `docker buildx`. Per ADR-010:
# FIPS-validated cryptography in all modes. Image is signed with cosign keyless
# via GitHub Actions OIDC at release time (CI workflow, not in this Dockerfile).
#
# Build:
#   docker buildx build --platform linux/amd64,linux/arm64 -t expose:dev .
#
# Run (single-arch local):
#   docker build -t expose:dev .
#   docker run --rm -e EXPOSE_DB_HOST=... -p 8000:8000 expose:dev

# === Stage 1: builder — install deps, build wheel ===========================
ARG PYTHON_VERSION=3.12
FROM python:${PYTHON_VERSION}-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

# Install uv (per ADR-001 / CONTRIBUTING.md — standardized dependency manager).
RUN pip install --no-cache-dir uv

# Build deps for asyncpg / cryptography wheels (most ship binary, but FIPS
# builds may need to compile against system OpenSSL).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
        libssl-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy dependency manifest first for layer caching.
COPY pyproject.toml ./
COPY README.md LICENSE SECURITY.md ETHICS.md ./

# Resolve and install runtime deps into a venv we'll copy to runtime.
RUN uv venv /opt/venv \
    && . /opt/venv/bin/activate \
    && uv pip install --no-cache ".[collectors-dns]"

# Copy source after deps are cached.
COPY src ./src
COPY schemas ./schemas
COPY alembic ./alembic
COPY alembic.ini ./

# Install the package itself.
RUN . /opt/venv/bin/activate && uv pip install --no-cache --no-deps .

# === Stage 2: runtime — minimal image, non-root ============================
FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime

ARG BUILD_VERSION=0.1.0.dev0
ARG VCS_REF=unknown

LABEL org.opencontainers.image.title="EXPOSE Core" \
      org.opencontainers.image.description="External Attack Surface Intelligence — deterministic discovery + bounded LLM enrichment + signed JSON artifacts" \
      org.opencontainers.image.source="https://github.com/pitt-street-labs/expose" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Korlogos / Pitt Street Labs" \
      org.opencontainers.image.version="${BUILD_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}" \
    EXPOSE_LOG_LEVEL=info

# Runtime libs only — libpq for asyncpg, ca-certs for outbound TLS to
# collectors and LLM providers, libssl for FIPS-validated crypto.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpq5 \
        libssl3 \
        ca-certificates \
        tini \
    && rm -rf /var/lib/apt/lists/*

# Non-root user — required by FedRAMP / NIST 800-53 baseline (CM-7 least
# functionality + AC-6 least privilege).
RUN groupadd --system --gid 1000 expose \
    && useradd --system --uid 1000 --gid expose --shell /bin/false --no-create-home expose

# Copy the prebuilt venv from the builder stage.
COPY --from=builder --chown=expose:expose /opt/venv /opt/venv

# Copy application source, schemas, and migrations needed at runtime.
COPY --from=builder --chown=expose:expose /build/src /app/src
COPY --from=builder --chown=expose:expose /build/schemas /app/schemas
COPY --from=builder --chown=expose:expose /build/alembic /app/alembic
COPY --from=builder --chown=expose:expose /build/alembic.ini /app/alembic.ini

WORKDIR /app
USER expose:expose

# tini reaps zombie children — important for the worker pattern where
# subprocess collectors may misbehave.
ENTRYPOINT ["/usr/bin/tini", "--"]

# Default command: print version. Real entry points (control-plane API,
# collector worker, scanner worker, llm worker) are launched via the
# `expose` CLI subcommands (serve, worker, scan, etc.).
CMD ["expose", "--version"]
