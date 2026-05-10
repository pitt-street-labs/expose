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
"""
from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("expose")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
