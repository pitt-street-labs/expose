"""Typed representation of observation property dicts.

The pipeline's ``_observation_properties()`` helper (in ``run_executor.py``)
merges an observation's ``structured_payload`` with collector provenance
metadata and returns a flat ``dict[str, Any]``.  The ``ObservationProps``
TypedDict captures the well-known keys that appear in **every** such dict,
regardless of collector.  Collector-specific fields live in the payload
models in ``collector_payloads.py``.

This module is **additive** -- existing code continues to use
``dict[str, Any]`` unchanged.  New code can narrow dicts to
``ObservationProps`` for better IDE completion and mypy checking.
"""

from __future__ import annotations

from typing import TypedDict


class ObservationProps(TypedDict, total=False):
    """Well-known keys present in every observation properties dict.

    ``total=False`` because not all keys are guaranteed on every dict --
    for example ``_warnings`` is only present when the observation had
    non-fatal warnings, and ``_lead_score`` / ``_priority_tier`` are
    only injected after lead scoring runs.

    Collector-specific payload fields (``record_type``, ``values``,
    ``open_ports``, ``tls_version``, etc.) are intentionally **not**
    listed here; use the typed payload models in
    ``expose.types.collector_payloads`` for those.
    """

    # -- Provenance metadata (injected by _observation_properties) --
    _collector_id: str
    _collector_version: str
    _observation_type: str
    _observed_at: str  # ISO 8601 timestamp
    _warnings: list[str]

    # -- Lead scoring metadata (injected post-scoring) --
    _lead_score: int
    _priority_tier: str  # e.g. "critical", "high", "medium", "low", "info"

    # -- Common payload fields shared by multiple collectors --
    record_type: str  # DNS record type, present in DNS-family collectors
    values: list[str]  # Resolved addresses or TXT values


__all__ = ["ObservationProps"]
