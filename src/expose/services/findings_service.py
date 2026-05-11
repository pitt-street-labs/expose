"""Service layer for prioritized findings (lead-scored entities).

Extracts findings business logic from the API route handler into a reusable
service class that receives a ``session_factory`` via dependency injection.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from expose.api.findings import (
    FindingEntry,
    FindingsResponse,
    _PLACEHOLDER_FINDINGS,
)
from expose.types.pipeline import FindingSignal


class FindingsService:
    """Queries and ranks entities by lead score and takeover risk.

    Uses a session factory rather than a single session because the findings
    endpoint may need to open multiple independent DB sessions (one for scored
    findings, one for takeover findings).
    """

    def __init__(self, session_factory: Any) -> None:
        self._session_factory = session_factory

    async def get_scored_findings(
        self,
        tenant_id: UUID,
    ) -> list[FindingEntry]:
        """Query entities with ``_lead_score`` in properties and build findings.

        Returns a list of ``FindingEntry`` objects for entities that have been
        scored by the ``LeadScoringEngine`` during pipeline execution.

        Returns an empty list when no session factory is available or no
        scored entities exist.
        """
        if self._session_factory is None:
            return []

        from sqlalchemy import select  # noqa: PLC0415

        from expose.db.models import Entity  # noqa: PLC0415

        async with self._session_factory() as session:
            stmt = (
                select(Entity)
                .where(Entity.tenant_id == tenant_id)
                .order_by(Entity.last_observed_at.desc())
                .limit(500)
            )
            result = await session.execute(stmt)
            rows = result.scalars().all()

        findings: list[FindingEntry] = []
        rank = 1
        for entity in rows:
            props = entity.properties or {}
            lead_score = props.get("_lead_score")
            if lead_score is None:
                continue

            # Coerce to int (may be stored as float in JSONB)
            try:
                score = int(lead_score)
            except (TypeError, ValueError):
                continue

            priority_tier = props.get("_priority_tier", "low")

            # Build signal list from stored properties
            signals: list[FindingSignal] = []
            for key, val in props.items():
                if key.startswith("_") or key in (
                    "collector_id",
                    "collector_version",
                ):
                    continue
                if isinstance(val, (int, float)) and key not in (
                    "lead_score",
                    "priority_tier",
                ):
                    signals.append(FindingSignal(signal=key, weight=val))

            findings.append(FindingEntry(
                rank=rank,
                entity_identifier=entity.canonical_identifier,
                entity_type=entity.entity_type,
                score=score,
                priority_tier=priority_tier,
                justification=(
                    f"{entity.canonical_identifier}: lead score {score} "
                    f"({priority_tier})"
                ),
                signals=signals,
            ))
            rank += 1

        # Sort by score descending for consistent ordering
        findings.sort(key=lambda f: f.score, reverse=True)
        return findings

    async def get_takeover_findings(
        self,
        tenant_id: UUID,
    ) -> list[FindingEntry]:
        """Query entities with ``_takeover_risk`` in properties and build findings.

        Returns a list of ``FindingEntry`` objects for entities flagged with
        subdomain takeover risk by the ``takeover_detection`` pipeline stage.
        """
        if self._session_factory is None:
            return []

        from sqlalchemy import select  # noqa: PLC0415

        from expose.db.models import Entity  # noqa: PLC0415

        async with self._session_factory() as session:
            stmt = (
                select(Entity)
                .where(Entity.tenant_id == tenant_id)
                .order_by(Entity.last_observed_at.desc())
                .limit(500)
            )
            result = await session.execute(stmt)
            rows = result.scalars().all()

        findings: list[FindingEntry] = []
        rank = 1
        for entity in rows:
            props = entity.properties or {}
            takeover = props.get("_takeover_risk")
            if not takeover:
                continue

            risk_level = takeover.get("risk_level", "high")
            score = 98 if risk_level == "critical" else 85
            provider = takeover.get("provider", "unknown")
            cname_target = takeover.get("cname_target", "unknown")

            findings.append(FindingEntry(
                rank=rank,
                entity_identifier=entity.canonical_identifier,
                entity_type=entity.entity_type,
                score=score,
                priority_tier="critical",
                justification=(
                    f"Subdomain takeover risk: CNAME points to {cname_target} "
                    f"({provider}) but the service no longer exists. An attacker "
                    f"can claim this service and hijack the subdomain."
                ),
                signals=[
                    FindingSignal(signal="dangling_cname", weight=50),
                    FindingSignal(signal=f"vulnerable_provider_{provider}", weight=30),
                    FindingSignal(signal="nxdomain_confirmed", weight=18),
                ],
            ))
            rank += 1

        return findings

    async def get_all_findings(
        self,
        tenant_id: UUID,
        limit: int,
        min_score: int,
    ) -> FindingsResponse:
        """Orchestrate scored + takeover findings, filter, sort, and rank.

        When real scored entities exist in the database, returns them with
        ``is_placeholder=False``. Otherwise falls back to placeholder data.
        """
        scored_findings = await self.get_scored_findings(tenant_id)
        takeover_findings = await self.get_takeover_findings(tenant_id)

        # Combine real findings from both sources
        real_findings = takeover_findings + scored_findings
        has_real_data = len(real_findings) > 0

        if has_real_data:
            all_entries = real_findings
        else:
            # No DB or no scored entities -- use placeholder data
            all_entries = [
                FindingEntry(rank=1, **item)  # rank re-assigned below
                for item in _PLACEHOLDER_FINDINGS
            ]

        total_scored = len(all_entries)

        # Filter by min_score, sort descending, apply limit
        filtered = [f for f in all_entries if f.score >= min_score]
        filtered.sort(key=lambda f: f.score, reverse=True)
        filtered = filtered[:limit]

        # Re-assign sequential ranks after filtering
        ranked = [
            FindingEntry(
                rank=idx + 1,
                entity_identifier=f.entity_identifier,
                entity_type=f.entity_type,
                score=f.score,
                priority_tier=f.priority_tier,
                justification=f.justification,
                signals=f.signals,
            )
            for idx, f in enumerate(filtered)
        ]

        return FindingsResponse(
            tenant_id=tenant_id,
            findings=ranked,
            total_scored=total_scored,
            generated_at=datetime.now(tz=UTC),
            is_placeholder=not has_real_data,
        )
