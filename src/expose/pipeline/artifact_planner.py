"""Artifact planner — evaluates coverage and completeness before artifact generation.

Before committing to artifact generation (SPEC §2.2 Stage 6), the planner
assesses whether the current run's data is sufficient to produce a useful
canonical artifact.  It inspects dispatch success/failure rates, entity
counts, attribution coverage, and collector health to produce an
``ArtifactReadiness`` verdict.

The planner is intentionally stateless and synchronous — it operates on
summary statistics extracted from a ``RunResult`` rather than querying
databases directly.  This keeps it testable in isolation and avoids
coupling to the async repository layer.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class CoverageGap(BaseModel):
    """A single gap in collector coverage for a seed."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    collector_id: str
    seed_value: str
    reason: str  # "collector_failed", "health_check_failed", "tier3_denied", "no_observations"
    severity: str  # "critical", "warning", "info"


class ArtifactReadiness(BaseModel):
    """Verdict on whether a run's data is sufficient for artifact generation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    ready: bool
    confidence: float = Field(ge=0.0, le=1.0)
    entity_count: int
    attributed_count: int  # entities with confirmed/high/medium
    unattributed_count: int
    coverage_gaps: list[CoverageGap]
    recommendations: list[str]
    estimated_artifact_size_kb: float


class ArtifactPlanner:
    """Evaluates whether a completed run has sufficient data for artifact generation.

    Constructed with a minimum confidence threshold (default 0.5).  The
    ``evaluate`` method accepts summary statistics and returns an
    ``ArtifactReadiness`` verdict.
    """

    def __init__(self, min_confidence: float = 0.5) -> None:
        self._min_confidence = min_confidence

    def evaluate(
        self,
        *,
        total_seeds: int,
        expanded_seeds: int,
        successful_dispatches: int,
        failed_dispatches: int,
        denied_dispatches: int,
        total_observations: int,
        entity_count: int,
        attributed_count: int,
        collectors_used: list[str],
        collectors_failed: list[str],
    ) -> ArtifactReadiness:
        """Assess readiness for artifact generation.

        Parameters
        ----------
        total_seeds:
            Number of original seeds submitted for the run.
        expanded_seeds:
            Number of seeds after deterministic expansion (Stage 1).
        successful_dispatches:
            Number of (seed, collector) pairs that completed successfully.
        failed_dispatches:
            Number of (seed, collector) pairs that failed (collector error,
            health-check failure, exception, etc.).
        denied_dispatches:
            Number of (seed, collector) pairs denied by the Tier-3 gate.
        total_observations:
            Total observations returned across all successful dispatches.
        entity_count:
            Number of distinct entities upserted into the observation graph.
        attributed_count:
            Number of entities with attribution tier confirmed/high/medium.
        collectors_used:
            IDs of all collectors that were dispatched to.
        collectors_failed:
            IDs of collectors that failed at least once.

        Returns
        -------
        ArtifactReadiness
            Verdict including confidence score, coverage gaps, and
            recommendations.
        """
        total_dispatches = successful_dispatches + failed_dispatches + denied_dispatches
        confidence = successful_dispatches / max(total_dispatches, 1)
        ready = confidence >= self._min_confidence and entity_count > 0

        unattributed_count = entity_count - attributed_count

        # --- Build coverage gaps ---
        coverage_gaps: list[CoverageGap] = []
        for collector_id in collectors_failed:
            coverage_gaps.append(
                CoverageGap(
                    collector_id=collector_id,
                    seed_value="*",
                    reason="collector_failed",
                    severity="critical" if collector_id not in collectors_used else "warning",
                )
            )

        if denied_dispatches > 0:
            coverage_gaps.append(
                CoverageGap(
                    collector_id="*",
                    seed_value="*",
                    reason="tier3_denied",
                    severity="warning",
                )
            )

        if total_observations == 0 and successful_dispatches > 0:
            coverage_gaps.append(
                CoverageGap(
                    collector_id="*",
                    seed_value="*",
                    reason="no_observations",
                    severity="critical",
                )
            )

        # --- Build recommendations ---
        recommendations: list[str] = []
        high_denial_threshold = 0.5

        # All Tier-1 (passive) collectors failed
        if failed_dispatches > 0 and successful_dispatches == 0 and denied_dispatches == 0:
            recommendations.append(
                "All passive collectors failed — check network connectivity"
            )

        # High denial rate
        if total_dispatches > 0 and denied_dispatches / total_dispatches > high_denial_threshold:
            recommendations.append(
                "High denial rate — review authorization scope"
            )

        # Zero attributed entities
        if entity_count == 0 and total_observations == 0:
            recommendations.append(
                "No entities attributed — check rule pack configuration"
            )

        # Entities discovered but none attributed
        if entity_count > 0 and attributed_count == 0:
            recommendations.append(
                "Entities discovered but none attributed"
            )

        # Estimated artifact size: ~2.5 KB per entity + 10 KB envelope overhead
        estimated_artifact_size_kb = entity_count * 2.5 + 10.0

        return ArtifactReadiness(
            ready=ready,
            confidence=confidence,
            entity_count=entity_count,
            attributed_count=attributed_count,
            unattributed_count=unattributed_count,
            coverage_gaps=coverage_gaps,
            recommendations=recommendations,
            estimated_artifact_size_kb=estimated_artifact_size_kb,
        )


__all__ = [
    "ArtifactPlanner",
    "ArtifactReadiness",
    "CoverageGap",
]
