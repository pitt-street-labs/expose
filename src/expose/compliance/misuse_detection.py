"""Heuristic misuse-detection patterns for EXPOSE EASI platform.

Flags potentially unauthorized scanning behavior by evaluating run metadata
against configurable thresholds.  This is **advisory only** -- it produces
alerts for operator review, not enforcement.  Enforcement is handled by the
scope-gating layer (per SPEC section 6, collector tier gating).

Indicators checked:

- **Scope drift**: many discovered entities fall outside the explicit scope.
- **Excessive Tier-3**: unusually high active-probe dispatch rate.
- **High denial rate**: many Tier-3 denials, suggesting scope-boundary probing.
- **Unusual hours**: runs triggered outside configured business hours.

Design notes:

- All models use ``ConfigDict(extra="forbid", frozen=True)`` per project
  convention (immutable value objects).
- Thresholds are injectable via ``MisuseThresholds``; callers can tighten
  or loosen per tenant policy.
- Small runs (below ``min_dispatches_for_check``) skip rate-based checks
  to avoid noisy false positives.

References:
    - ADR-008: Ethics framework, authorized use only
    - ETHICS.md: EXPOSE ethical scanning principles
    - Issue #33: Misuse-detection patterns
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict

logger = logging.getLogger(__name__)

# Severity breakpoints for _severity_for_pct.
_CRITICAL_THRESHOLD: float = 0.8
_WARNING_THRESHOLD: float = 0.5


class MisuseIndicator(StrEnum):
    """Categories of suspicious scanning behavior."""

    SCOPE_DRIFT = "scope_drift"
    EXCESSIVE_TIER3 = "excessive_tier3"
    CROSS_TENANT_PATTERN = "cross_tenant"
    RAPID_SCOPE_EXPANSION = "rapid_scope"
    UNUSUAL_HOURS = "unusual_hours"
    HIGH_DENIAL_RATE = "high_denial_rate"


class MisuseThresholds(BaseModel):
    """Configurable thresholds for misuse-detection heuristics.

    Defaults are tuned for a typical enterprise operator.  Per-tenant
    overrides can tighten or loosen as appropriate.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    scope_drift_pct: float = 0.3
    """Flag if >30% of discovered entities are outside explicit scope."""

    tier3_rate_pct: float = 0.8
    """Flag if >80% of dispatches are Tier-3 active probes."""

    denial_rate_pct: float = 0.5
    """Flag if >50% of dispatch requests were denied."""

    business_hours_start: int = 6
    """Start of normal business hours (inclusive), 24-hour clock."""

    business_hours_end: int = 22
    """End of normal business hours (exclusive), 24-hour clock."""

    min_dispatches_for_check: int = 10
    """Minimum total dispatches before rate-based checks apply."""


class MisuseAlert(BaseModel):
    """An advisory alert produced by misuse-detection heuristics.

    These are informational -- they surface suspicious patterns for
    operator review, not enforcement actions.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    indicator: MisuseIndicator
    tenant_id: UUID
    severity: str
    description: str
    evidence: dict[str, Any]
    detected_at: datetime
    run_id: UUID | None = None


def _severity_for_pct(pct: float) -> str:
    """Map a percentage to an advisory severity level.

    - >= 0.8 (80%) -> "critical"
    - >= 0.5 (50%) -> "warning"
    - below          -> "info"
    """
    if pct >= _CRITICAL_THRESHOLD:
        return "critical"
    if pct >= _WARNING_THRESHOLD:
        return "warning"
    return "info"


class MisuseDetector:
    """Evaluates run metadata for patterns indicating potential misuse.

    This is advisory -- it flags suspicious patterns for operator review,
    not enforcement.  Enforcement is handled by the scope-gating layer.
    """

    def __init__(self, thresholds: MisuseThresholds | None = None) -> None:
        self._thresholds = thresholds or MisuseThresholds()

    def check_scope_drift(
        self,
        in_scope_count: int,
        out_of_scope_count: int,
        tenant_id: UUID,
        run_id: UUID,
    ) -> MisuseAlert | None:
        """Flag if >threshold% of discovered entities are outside scope."""
        total = in_scope_count + out_of_scope_count
        if total == 0:
            return None

        drift_pct = out_of_scope_count / total
        if drift_pct <= self._thresholds.scope_drift_pct:
            return None

        severity = _severity_for_pct(drift_pct)
        alert = MisuseAlert(
            indicator=MisuseIndicator.SCOPE_DRIFT,
            tenant_id=tenant_id,
            severity=severity,
            description=(
                f"Scope drift detected: {out_of_scope_count}/{total} "
                f"({drift_pct:.0%}) entities outside explicit scope"
            ),
            evidence={
                "in_scope_count": in_scope_count,
                "out_of_scope_count": out_of_scope_count,
                "drift_pct": round(drift_pct, 4),
            },
            detected_at=datetime.now(UTC),
            run_id=run_id,
        )
        logger.warning(
            "Misuse indicator: scope drift",
            extra={
                "tenant_id": str(tenant_id),
                "run_id": str(run_id),
                "drift_pct": round(drift_pct, 4),
                "severity": severity,
            },
        )
        return alert

    def check_tier3_rate(
        self,
        tier3_dispatches: int,
        total_dispatches: int,
        tenant_id: UUID,
        run_id: UUID,
    ) -> MisuseAlert | None:
        """Flag if Tier-3 active probes exceed threshold% of total dispatches."""
        if total_dispatches < self._thresholds.min_dispatches_for_check:
            return None

        rate = tier3_dispatches / total_dispatches
        if rate <= self._thresholds.tier3_rate_pct:
            return None

        severity = _severity_for_pct(rate)
        alert = MisuseAlert(
            indicator=MisuseIndicator.EXCESSIVE_TIER3,
            tenant_id=tenant_id,
            severity=severity,
            description=(
                f"Excessive Tier-3 dispatch rate: {tier3_dispatches}/{total_dispatches} "
                f"({rate:.0%}) are active probes"
            ),
            evidence={
                "tier3_dispatches": tier3_dispatches,
                "total_dispatches": total_dispatches,
                "tier3_rate": round(rate, 4),
            },
            detected_at=datetime.now(UTC),
            run_id=run_id,
        )
        logger.warning(
            "Misuse indicator: excessive Tier-3",
            extra={
                "tenant_id": str(tenant_id),
                "run_id": str(run_id),
                "tier3_rate": round(rate, 4),
                "severity": severity,
            },
        )
        return alert

    def check_denial_rate(
        self,
        denied: int,
        total: int,
        tenant_id: UUID,
        run_id: UUID,
    ) -> MisuseAlert | None:
        """Flag if denial rate suggests probing scope boundaries."""
        if total < self._thresholds.min_dispatches_for_check:
            return None

        rate = denied / total
        if rate <= self._thresholds.denial_rate_pct:
            return None

        severity = _severity_for_pct(rate)
        alert = MisuseAlert(
            indicator=MisuseIndicator.HIGH_DENIAL_RATE,
            tenant_id=tenant_id,
            severity=severity,
            description=(
                f"High denial rate: {denied}/{total} "
                f"({rate:.0%}) dispatch requests denied"
            ),
            evidence={
                "denied": denied,
                "total": total,
                "denial_rate": round(rate, 4),
            },
            detected_at=datetime.now(UTC),
            run_id=run_id,
        )
        logger.warning(
            "Misuse indicator: high denial rate",
            extra={
                "tenant_id": str(tenant_id),
                "run_id": str(run_id),
                "denial_rate": round(rate, 4),
                "severity": severity,
            },
        )
        return alert

    def check_run_timing(
        self,
        run_timestamp: datetime,
        tenant_id: UUID,
        run_id: UUID,
    ) -> MisuseAlert | None:
        """Flag runs outside configured business hours."""
        hour = run_timestamp.hour
        start = self._thresholds.business_hours_start
        end = self._thresholds.business_hours_end

        if start <= hour < end:
            return None

        alert = MisuseAlert(
            indicator=MisuseIndicator.UNUSUAL_HOURS,
            tenant_id=tenant_id,
            severity="info",
            description=(
                f"Run triggered at {run_timestamp.strftime('%H:%M')} UTC, "
                f"outside business hours ({start:02d}:00-{end:02d}:00)"
            ),
            evidence={
                "run_hour": hour,
                "business_hours_start": start,
                "business_hours_end": end,
                "run_timestamp": run_timestamp.isoformat(),
            },
            detected_at=datetime.now(UTC),
            run_id=run_id,
        )
        logger.info(
            "Misuse indicator: unusual hours",
            extra={
                "tenant_id": str(tenant_id),
                "run_id": str(run_id),
                "run_hour": hour,
            },
        )
        return alert

    def evaluate_run(
        self,
        *,
        tenant_id: UUID,
        run_id: UUID,
        in_scope: int,
        out_of_scope: int,
        tier3_dispatches: int,
        total_dispatches: int,
        denied: int,
        run_timestamp: datetime,
    ) -> list[MisuseAlert]:
        """Run all checks and return any triggered alerts.

        This is the primary entry point for batch evaluation of a
        completed (or in-progress) run.  Individual ``check_*`` methods
        can also be called independently.
        """
        alerts: list[MisuseAlert] = []

        scope_alert = self.check_scope_drift(
            in_scope_count=in_scope,
            out_of_scope_count=out_of_scope,
            tenant_id=tenant_id,
            run_id=run_id,
        )
        if scope_alert is not None:
            alerts.append(scope_alert)

        tier3_alert = self.check_tier3_rate(
            tier3_dispatches=tier3_dispatches,
            total_dispatches=total_dispatches,
            tenant_id=tenant_id,
            run_id=run_id,
        )
        if tier3_alert is not None:
            alerts.append(tier3_alert)

        denial_alert = self.check_denial_rate(
            denied=denied,
            total=total_dispatches,
            tenant_id=tenant_id,
            run_id=run_id,
        )
        if denial_alert is not None:
            alerts.append(denial_alert)

        timing_alert = self.check_run_timing(
            run_timestamp=run_timestamp,
            tenant_id=tenant_id,
            run_id=run_id,
        )
        if timing_alert is not None:
            alerts.append(timing_alert)

        return alerts
