"""Run scheduler — triggers pipeline runs on per-tenant cron schedules.

The ``RunScheduler`` manages a set of ``ScheduleEntry`` objects (one per tenant)
and runs a background loop that checks schedules every 60 seconds.  When a
schedule fires, it invokes a callback (typically wired to
``RunExecutor.execute``) with the tenant's collector list and seed set.

The cron evaluator is implemented inline (``CronExpression``) to avoid pulling
in ``croniter`` or ``APScheduler`` as dependencies.  It supports standard
5-field expressions: minute, hour, day-of-month, month, day-of-week, including
wildcards (``*``), specific values, ranges (``1-5``), steps (``*/5``), and
comma-separated lists (``1,3,5``).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

# === Cron expression parser ===================================================

# Symbolic day-of-week names (case-insensitive) mapped to cron integers.
_DOW_NAMES: dict[str, int] = {
    "sun": 0,
    "mon": 1,
    "tue": 2,
    "wed": 3,
    "thu": 4,
    "fri": 5,
    "sat": 6,
}

# Symbolic month names (case-insensitive) mapped to month numbers.
_MONTH_NAMES: dict[str, int] = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}

# Inclusive ranges for each field position.
_FIELD_RANGES: list[tuple[int, int]] = [
    (0, 59),   # minute
    (0, 23),   # hour
    (1, 31),   # day of month
    (1, 12),   # month
    (0, 6),    # day of week  (0 = Sunday)
]

_FIELD_NAMES: list[str] = ["minute", "hour", "day-of-month", "month", "day-of-week"]

# Field position constants to avoid magic numbers.
_POS_MONTH = 3
_POS_DOW = 4

# Name-to-int lookup tables keyed by field position.
_NAME_TABLES: dict[int, dict[str, int]] = {
    _POS_MONTH: _MONTH_NAMES,
    _POS_DOW: _DOW_NAMES,
}


def _resolve_name(token: str, position: int) -> str:
    """Replace symbolic month/dow names with their integer equivalents."""
    table = _NAME_TABLES.get(position)
    if table is not None:
        lower = token.lower()
        if lower in table:
            return str(table[lower])
    return token


def _parse_element(element: str, position: int, lo: int, hi: int, field_name: str) -> set[int]:
    """Parse one comma-separated element of a cron field into matching ints."""
    expr = _resolve_name(element.strip(), position)
    if not expr:
        msg = f"Empty element in {field_name} field"
        raise ValueError(msg)

    # Handle step notation (*/S or N-M/S)
    step = 1
    if "/" in expr:
        base, step_str = expr.split("/", maxsplit=1)
        try:
            step = int(step_str)
        except ValueError:
            msg = f"Invalid step value '{step_str}' in {field_name} field"
            raise ValueError(msg) from None
        if step < 1:
            msg = f"Step must be >= 1, got {step} in {field_name} field"
            raise ValueError(msg)
        expr = base

    if expr == "*":
        return set(range(lo, hi + 1, step))

    if "-" in expr:
        return _parse_range(expr, position, lo, hi, step, field_name)

    # Single value.
    try:
        val = int(expr)
    except ValueError:
        msg = f"Invalid value '{expr}' in {field_name} field"
        raise ValueError(msg) from None
    if val < lo or val > hi:
        msg = f"Value {val} out of bounds [{lo}-{hi}] in {field_name} field"
        raise ValueError(msg)
    return {val}


def _parse_range(
    token: str, position: int, lo: int, hi: int, step: int, field_name: str
) -> set[int]:
    """Parse a range expression (``N-M``) into a set of ints."""
    range_parts = token.split("-", maxsplit=1)
    try:
        r_lo = int(_resolve_name(range_parts[0], position))
        r_hi = int(_resolve_name(range_parts[1], position))
    except ValueError:
        msg = f"Invalid range '{token}' in {field_name} field"
        raise ValueError(msg) from None
    if r_lo < lo or r_hi > hi:
        msg = f"Range {r_lo}-{r_hi} out of bounds [{lo}-{hi}] in {field_name} field"
        raise ValueError(msg)
    if r_lo > r_hi:
        msg = f"Range start {r_lo} > end {r_hi} in {field_name} field"
        raise ValueError(msg)
    return set(range(r_lo, r_hi + 1, step))


def _parse_field(raw: str, position: int) -> frozenset[int]:
    """Parse a single cron field into a set of matching integer values.

    Supports: ``*``, ``N``, ``N-M``, ``*/S``, ``N-M/S``, ``N,M,...``.

    Raises ``ValueError`` for out-of-range values or malformed tokens.
    """
    lo, hi = _FIELD_RANGES[position]
    field_name = _FIELD_NAMES[position]
    values: set[int] = set()

    for element in raw.split(","):
        values.update(_parse_element(element, position, lo, hi, field_name))

    if not values:
        msg = f"No values produced for {field_name} field"
        raise ValueError(msg)

    return frozenset(values)


class CronExpression:
    """Parsed 5-field cron expression with matching and next-occurrence logic.

    Standard fields: ``minute hour day-of-month month day-of-week``.

    Day-of-week uses 0 = Sunday (ISO weekday is converted internally).
    """

    __slots__ = ("_days", "_dows", "_hours", "_minutes", "_months", "_raw")

    def __init__(self, expression: str) -> None:
        parts = expression.strip().split()
        if len(parts) != 5:  # noqa: PLR2004
            msg = (
                f"Cron expression must have exactly 5 fields, got {len(parts)}: "
                f"{expression!r}"
            )
            raise ValueError(msg)

        self._raw = expression.strip()
        self._minutes = _parse_field(parts[0], 0)
        self._hours = _parse_field(parts[1], 1)
        self._days = _parse_field(parts[2], 2)
        self._months = _parse_field(parts[3], 3)
        self._dows = _parse_field(parts[4], 4)

    @property
    def expression(self) -> str:
        """Return the original cron expression string."""
        return self._raw

    def _iso_to_cron_dow(self, iso_weekday: int) -> int:
        """Convert Python ``datetime.isoweekday()`` (1=Mon..7=Sun) to cron (0=Sun..6=Sat)."""
        return iso_weekday % 7

    def _check_day(self, dt: datetime) -> bool:
        """Check day-of-month / day-of-week constraints using POSIX OR semantics."""
        cron_dow = self._iso_to_cron_dow(dt.isoweekday())
        dom_is_star = self._days == frozenset(range(1, 32))
        dow_is_star = self._dows == frozenset(range(0, 7))

        if dom_is_star and dow_is_star:
            return True
        if dom_is_star:
            return cron_dow in self._dows
        if dow_is_star:
            return dt.day in self._days
        # Both restricted — OR semantics per POSIX cron.
        return dt.day in self._days or cron_dow in self._dows

    def matches(self, dt: datetime) -> bool:
        """Return ``True`` if *dt* falls on a minute matching this schedule.

        The datetime is evaluated at minute granularity (seconds and below are
        ignored).
        """
        if dt.minute not in self._minutes:
            return False
        if dt.hour not in self._hours:
            return False
        if dt.month not in self._months:
            return False
        return self._check_day(dt)

    def next_occurrence(self, from_dt: datetime) -> datetime:
        """Return the next datetime *after* ``from_dt`` that matches.

        Searches minute-by-minute up to 366 days ahead.  Raises
        ``RuntimeError`` if no match is found (should not happen for valid
        expressions).
        """
        # Snap to the start of the next minute.
        candidate = from_dt.replace(second=0, microsecond=0) + timedelta(minutes=1)

        # Upper bound: 366 days = 527040 minutes.  We skip whole hours/days
        # when possible to keep the search fast.
        limit = candidate + timedelta(days=366)

        while candidate < limit:
            if candidate.month not in self._months:
                # Jump to the first day of the next month.
                if candidate.month == 12:  # noqa: PLR2004
                    candidate = candidate.replace(
                        year=candidate.year + 1, month=1, day=1, hour=0, minute=0
                    )
                else:
                    candidate = candidate.replace(
                        month=candidate.month + 1, day=1, hour=0, minute=0
                    )
                continue

            if not self._check_day(candidate):
                candidate = candidate.replace(hour=0, minute=0) + timedelta(days=1)
                continue

            if candidate.hour not in self._hours:
                candidate = candidate.replace(minute=0) + timedelta(hours=1)
                continue

            if candidate.minute not in self._minutes:
                candidate += timedelta(minutes=1)
                continue

            return candidate

        msg = f"No matching time found within 366 days for expression {self._raw!r}"
        raise RuntimeError(msg)

    def __repr__(self) -> str:
        return f"CronExpression({self._raw!r})"


# === Schedule entry model =====================================================


class ScheduleEntry(BaseModel):
    """Immutable record of a tenant's run schedule."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    cron_expression: str
    collector_ids: list[str] = Field(default_factory=list)
    seeds: list[dict] = Field(default_factory=list)
    last_run_at: datetime | None = None
    next_run_at: datetime | None = None
    enabled: bool = True


# === Run scheduler ============================================================

# Type alias for the callback invoked when a schedule fires.
OnRunTrigger = Callable[[UUID, list[str], list[dict]], Awaitable[None]]

# How often the scheduler wakes to check schedules (seconds).
_CHECK_INTERVAL_SECONDS = 60


class RunScheduler:
    """Manages per-tenant cron schedules and triggers pipeline runs.

    The scheduler keeps schedules in memory.  Production deployments will
    persist them via the tenant config API (Phase 3).

    Parameters
    ----------
    on_run_trigger:
        Async callback invoked when a schedule fires.  Receives
        ``(tenant_id, collector_ids, seeds)``.  The callback is responsible
        for actually creating and executing the run (e.g., via
        ``RunExecutor.execute``).
    """

    def __init__(self, on_run_trigger: OnRunTrigger) -> None:
        self._on_run_trigger = on_run_trigger
        self._schedules: dict[UUID, ScheduleEntry] = {}
        self._cron_cache: dict[str, CronExpression] = {}

    def _get_cron(self, expression: str) -> CronExpression:
        """Return a cached ``CronExpression`` for *expression*."""
        if expression not in self._cron_cache:
            self._cron_cache[expression] = CronExpression(expression)
        return self._cron_cache[expression]

    def add_schedule(
        self,
        tenant_id: UUID,
        cron_expression: str,
        collector_ids: list[str],
        seeds: list[dict],
    ) -> ScheduleEntry:
        """Add or replace the schedule for *tenant_id*.

        Validates the cron expression eagerly — raises ``ValueError`` if
        invalid.

        Returns the created ``ScheduleEntry``.
        """
        cron = self._get_cron(cron_expression)

        now = datetime.now(UTC)
        next_run = cron.next_occurrence(now)

        entry = ScheduleEntry(
            tenant_id=tenant_id,
            cron_expression=cron_expression,
            collector_ids=collector_ids,
            seeds=seeds,
            next_run_at=next_run,
        )
        self._schedules[tenant_id] = entry

        logger.info(
            "Schedule added for tenant %s: %s (next run %s)",
            tenant_id,
            cron_expression,
            next_run.isoformat(),
        )
        return entry

    def remove_schedule(self, tenant_id: UUID) -> bool:
        """Remove the schedule for *tenant_id*.  Returns ``True`` if it existed."""
        removed = self._schedules.pop(tenant_id, None)
        if removed is not None:
            logger.info("Schedule removed for tenant %s", tenant_id)
            return True
        return False

    def get_schedule(self, tenant_id: UUID) -> ScheduleEntry | None:
        """Return the schedule entry for *tenant_id*, or ``None``."""
        return self._schedules.get(tenant_id)

    def list_schedules(self) -> list[ScheduleEntry]:
        """Return all registered schedule entries."""
        return list(self._schedules.values())

    async def run(self, shutdown_event: asyncio.Event) -> None:
        """Main scheduler loop.

        Checks all schedules every 60 seconds.  When a schedule's
        ``next_run_at`` is at or before the current time, the run trigger
        callback is invoked and ``next_run_at`` is advanced.

        The loop exits when *shutdown_event* is set.
        """
        logger.info("Run scheduler started")

        while not shutdown_event.is_set():
            now = datetime.now(UTC)

            for tenant_id in list(self._schedules):
                entry = self._schedules.get(tenant_id)
                if entry is None:
                    continue

                if not entry.enabled:
                    continue

                if entry.next_run_at is None:
                    continue

                if now < entry.next_run_at:
                    continue

                # Fire the trigger.
                logger.info("Triggering run for tenant %s", tenant_id)
                try:
                    await self._on_run_trigger(
                        tenant_id,
                        list(entry.collector_ids),
                        list(entry.seeds),
                    )
                except Exception:
                    logger.exception(
                        "Run trigger failed for tenant %s", tenant_id
                    )

                # Advance next_run_at regardless of trigger success — we don't
                # want a stuck trigger to fire in a tight loop.
                cron = self._get_cron(entry.cron_expression)
                next_run = cron.next_occurrence(now)

                self._schedules[tenant_id] = entry.model_copy(
                    update={
                        "last_run_at": now,
                        "next_run_at": next_run,
                    },
                )

            # Wait for the check interval or shutdown, whichever comes first.
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(
                    shutdown_event.wait(),
                    timeout=_CHECK_INTERVAL_SECONDS,
                )

        logger.info("Run scheduler stopped")


__all__ = [
    "CronExpression",
    "OnRunTrigger",
    "RunScheduler",
    "ScheduleEntry",
]
