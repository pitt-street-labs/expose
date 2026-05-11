"""M&A seed expansion — generate new seeds from M&A discovery observations.

When the ``ma-discovery`` collector finds corporate acquisitions, the acquired
companies' domains and organization names become new seeds for further
collection. This module converts those observations into ``Seed`` objects
that the pipeline can feed to subsequent collector rounds.

Depth limiting:
- ``max_depth=0`` — expansion disabled (same as ``enabled=False``)
- ``max_depth=1`` — direct acquisitions only: domain seeds generated,
  but no recursive organization seeds (no transitive M&A chase)
- ``max_depth=2+`` — recursive: also generates organization seeds for
  acquired companies so the pipeline can discover *their* acquisitions

The ``max_acquisitions`` cap prevents runaway expansion for conglomerates
with hundreds of subsidiaries.

This module is pure — no I/O, no side effects. It operates on in-memory
``Observation`` objects produced by the ``ma-discovery`` collector.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from expose.collectors.base import Observation, Seed, SeedType


class MAExpansionConfig(BaseModel):
    """Configuration for M&A seed expansion.

    Controls whether expansion runs, how deep it recurses, and how many
    acquisitions are processed per expansion round.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = True
    max_depth: int = Field(default=1, ge=0, le=3)
    max_acquisitions: int = Field(default=20, ge=1, le=100)


class AcquisitionRecord(BaseModel):
    """Structured representation of a single corporate acquisition.

    Extracted from an ``Observation.structured_payload`` emitted by the
    ``ma-discovery`` collector. This model validates and normalizes the
    payload fields into a typed record for downstream processing.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    parent_organization: str = Field(min_length=1)
    acquired_organization: str = Field(min_length=1)
    acquired_domains: list[str] = Field(default_factory=list)
    acquisition_date: str | None = None
    source: str = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    attribution_source: str = "transitive_ma"


def _is_ma_observation(obs: Observation) -> bool:
    """Return True if ``obs`` was emitted by the ma-discovery collector."""
    payload = obs.structured_payload
    return (
        payload.get("_collector_id") == "ma-discovery"
        and payload.get("relationship_type") == "acquired_by"
    )


def _extract_acquisition_record(
    payload: dict[str, Any],
) -> AcquisitionRecord | None:
    """Try to build an ``AcquisitionRecord`` from observation payload.

    Returns ``None`` if the payload is malformed or missing required fields.
    """
    try:
        return AcquisitionRecord(
            parent_organization=payload.get("parent_organization", ""),
            acquired_organization=payload.get("acquired_organization", ""),
            acquired_domains=payload.get("acquired_domains", []),
            acquisition_date=payload.get("acquisition_date"),
            source=payload.get("source", ""),
            confidence=payload.get("confidence", 0.5),
            attribution_source=payload.get("attribution_source", "transitive_ma"),
        )
    except Exception:
        return None


def expand_ma_seeds(
    observations: list[Observation],
    config: MAExpansionConfig | None = None,
) -> list[Seed]:
    """Extract new domain/organization seeds from M&A discovery observations.

    Takes observations from the ``ma-discovery`` collector and generates new
    seeds for the acquired companies' domains. Depth-limited per config.

    Parameters
    ----------
    observations:
        Observation list (may include non-MA observations; they are filtered).
    config:
        Expansion configuration. ``None`` uses defaults (enabled, depth=1,
        max_acquisitions=20).

    Returns
    -------
    list[Seed]:
        New seeds generated from MA observations. Domain seeds for acquired
        company websites, and optionally organization seeds for recursive
        expansion (if ``max_depth > 1``).
    """
    if config is None:
        config = MAExpansionConfig()

    if not config.enabled or config.max_depth == 0:
        return []

    seeds: list[Seed] = []
    seen: set[tuple[str, str]] = set()  # (seed_type, value) dedup

    acquisition_count = 0

    for obs in observations:
        if not _is_ma_observation(obs):
            continue

        if acquisition_count >= config.max_acquisitions:
            break

        record = _extract_acquisition_record(obs.structured_payload)
        if record is None:
            continue

        acquisition_count += 1

        # Generate domain seeds for each acquired domain.
        for domain in record.acquired_domains:
            domain_lower = domain.strip().lower()
            if not domain_lower:
                continue
            key = (SeedType.DOMAIN.value, domain_lower)
            if key not in seen:
                seen.add(key)
                seeds.append(
                    Seed(
                        seed_type=SeedType.DOMAIN,
                        value=domain_lower,
                        properties={
                            "source": "ma_expansion",
                            "parent_organization": record.parent_organization,
                            "acquired_organization": record.acquired_organization,
                            "confidence": record.confidence,
                            "attribution_source": record.attribution_source,
                        },
                    )
                )

        # Generate organization seed for recursive expansion if depth > 1.
        if config.max_depth > 1:
            org_name = record.acquired_organization.strip()
            if org_name:
                key = (SeedType.ORGANIZATION.value, org_name.lower())
                if key not in seen:
                    seen.add(key)
                    seeds.append(
                        Seed(
                            seed_type=SeedType.ORGANIZATION,
                            value=org_name,
                            properties={
                                "source": "ma_expansion",
                                "parent_organization": record.parent_organization,
                                "confidence": record.confidence,
                                "attribution_source": record.attribution_source,
                            },
                        )
                    )

    return seeds


__all__ = [
    "AcquisitionRecord",
    "MAExpansionConfig",
    "expand_ma_seeds",
]
