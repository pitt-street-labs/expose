"""EXPOSE — continuous, attributed, cryptographically signed external attack surface intelligence.

EXPOSE Core (Apache 2.0) is the deterministic discovery and bounded-enrichment pipeline
producing signed JSON artifacts. See docs/SPEC.md for the comprehensive specification and
docs/positioning.md for strategic positioning.

Internal codename: FF6K.

Sub-packages:

- ``expose.types`` — Pydantic models mirroring the JSON Schemas in ``schemas/``.
- ``expose.db`` — SQLAlchemy ORM models and async engine factory (per ADR-002).
- ``expose.collectors`` — collector framework: ABC, tier gating, registry (per SPEC §6).
- ``expose.sanitization`` — Stage 3 sanitization + canonicalization (per SPEC §7).
- ``expose.broker`` — NATS JetStream client + worker base + stream setup (per SPEC §10.3, closed issue #36).
- ``expose.crypto`` — FIPS-validated SHA-256 / signing adapter (per ADR-010).
- ``expose.repositories`` — async tenant-scoped data access for entities/relationships/runs (per ADR-002 + ADR-007).
- ``expose.maintenance`` — scheduled maintenance jobs (retention pruning per ADR-008 §Layer 3).
- ``expose.secrets`` — pluggable per-tenant credentials backend (memory + future KMS/Vault per SPEC §10.1).
- ``expose.import_`` — third-party-config importers (SpiderFoot today; OWASP Amass / theHarvester future).
- ``expose.pipeline`` — Stage 1-4 orchestration: dispatcher, run executor, seed expansion (per SPEC §2.2).
- ``expose.observability`` — OpenTelemetry tracing + structured logging + metrics (per SPEC §10.2 / ADR-003).
"""
from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("expose")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
