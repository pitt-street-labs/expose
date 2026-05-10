"""EXPOSE — continuous, attributed, cryptographically signed external attack surface intelligence.

EXPOSE Core (Apache 2.0) is the deterministic discovery and bounded-enrichment pipeline
producing signed JSON artifacts. See docs/SPEC.md for the comprehensive specification and
docs/positioning.md for strategic positioning.

Internal codename: FF6K.
"""
from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("expose")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
