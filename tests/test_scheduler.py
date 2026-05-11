"""Tests for the RunScheduler and CronExpression components.

Coverage:

1.  CronExpression parsing — standard patterns accepted.
2.  CronExpression parsing — invalid expressions rejected.
3.  CronExpression.matches — daily at 02:00 UTC.
4.  CronExpression.matches — every-5-minutes pattern.
5.  CronExpression.matches — first-of-month pattern.
6.  CronExpression.matches — weekday-only pattern (Mon-Fri).
7.  CronExpression.matches — comma-separated values.
8.  CronExpression.next_occurrence — advances to correct time.
9.  CronExpression.next_occurrence — crosses month boundary.
10. CronExpression.next_occurrence — crosses year boundary.
11. Schedule CRUD — add_schedule creates entry.
12. Schedule CRUD — add_schedule replaces existing entry.
13. Schedule CRUD — remove_schedule returns True/False.
14. Schedule CRUD — get_schedule returns None for unknown tenant.
15. Schedule CRUD — list_schedules returns all entries.
16. Run loop — triggers callback at correct time.
17. Run loop — disabled schedules are skipped.
18. Run loop — callback exception does not crash the loop.
19. Schedule CRUD — invalid cron expression raises ValueError.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch
from uuid import UUID

import pytest

from expose.pipeline.scheduler import (
    CronExpression,
    RunScheduler,
    ScheduleEntry,
)

# === Synthetic IDs ============================================================

TENANT_A = UUID("018f1f00-0000-7000-8000-00000000A001")
TENANT_B = UUID("018f1f00-0000-7000-8000-00000000A002")


# === CronExpression parsing ===================================================


class TestCronExpressionParsing:
    """Verify that valid expressions parse and invalid ones raise."""

    def test_daily_at_0200(self) -> None:
        cron = CronExpression("0 2 * * *")
        assert cron.expression == "0 2 * * *"

    def test_every_5_minutes(self) -> None:
        cron = CronExpression("*/5 * * * *")
        assert cron.expression == "*/5 * * * *"

    def test_first_of_month(self) -> None:
        cron = CronExpression("0 0 1 * *")
        assert cron.expression == "0 0 1 * *"

    def test_weekdays_only(self) -> None:
        cron = CronExpression("0 9 * * 1-5")
        assert cron.expression == "0 9 * * 1-5"

    def test_comma_separated(self) -> None:
        cron = CronExpression("0 9,17 * * *")
        assert cron.expression == "0 9,17 * * *"

    def test_too_few_fields_raises(self) -> None:
        with pytest.raises(ValueError, match="5 fields"):
            CronExpression("0 2 * *")

    def test_too_many_fields_raises(self) -> None:
        with pytest.raises(ValueError, match="5 fields"):
            CronExpression("0 2 * * * *")

    def test_invalid_value_raises(self) -> None:
        with pytest.raises(ValueError, match="out of bounds"):
            CronExpression("60 * * * *")

    def test_invalid_range_raises(self) -> None:
        with pytest.raises(ValueError, match="out of bounds"):
            CronExpression("* 25 * * *")

    def test_empty_expression_raises(self) -> None:
        with pytest.raises(ValueError, match="5 fields"):
            CronExpression("")


# === CronExpression.matches ===================================================


class TestCronExpressionMatches:
    """Verify that matches() correctly identifies matching datetimes."""

    def test_daily_0200_matches_at_0200(self) -> None:
        cron = CronExpression("0 2 * * *")
        dt = datetime(2026, 5, 10, 2, 0, 0, tzinfo=UTC)
        assert cron.matches(dt) is True

    def test_daily_0200_rejects_0300(self) -> None:
        cron = CronExpression("0 2 * * *")
        dt = datetime(2026, 5, 10, 3, 0, 0, tzinfo=UTC)
        assert cron.matches(dt) is False

    def test_daily_0200_rejects_0201(self) -> None:
        cron = CronExpression("0 2 * * *")
        dt = datetime(2026, 5, 10, 2, 1, 0, tzinfo=UTC)
        assert cron.matches(dt) is False

    def test_every_5_minutes_matches_at_00(self) -> None:
        cron = CronExpression("*/5 * * * *")
        dt = datetime(2026, 5, 10, 14, 0, 0, tzinfo=UTC)
        assert cron.matches(dt) is True

    def test_every_5_minutes_matches_at_15(self) -> None:
        cron = CronExpression("*/5 * * * *")
        dt = datetime(2026, 5, 10, 14, 15, 0, tzinfo=UTC)
        assert cron.matches(dt) is True

    def test_every_5_minutes_rejects_at_03(self) -> None:
        cron = CronExpression("*/5 * * * *")
        dt = datetime(2026, 5, 10, 14, 3, 0, tzinfo=UTC)
        assert cron.matches(dt) is False

    def test_first_of_month_matches(self) -> None:
        cron = CronExpression("0 0 1 * *")
        dt = datetime(2026, 6, 1, 0, 0, 0, tzinfo=UTC)
        assert cron.matches(dt) is True

    def test_first_of_month_rejects_second(self) -> None:
        cron = CronExpression("0 0 1 * *")
        dt = datetime(2026, 6, 2, 0, 0, 0, tzinfo=UTC)
        assert cron.matches(dt) is False

    def test_weekdays_matches_monday(self) -> None:
        # 2026-05-11 is a Monday
        cron = CronExpression("0 9 * * 1-5")
        dt = datetime(2026, 5, 11, 9, 0, 0, tzinfo=UTC)
        assert cron.matches(dt) is True

    def test_weekdays_rejects_sunday(self) -> None:
        # 2026-05-10 is a Sunday
        cron = CronExpression("0 9 * * 1-5")
        dt = datetime(2026, 5, 10, 9, 0, 0, tzinfo=UTC)
        assert cron.matches(dt) is False

    def test_comma_list_matches(self) -> None:
        cron = CronExpression("0 9,17 * * *")
        assert cron.matches(datetime(2026, 5, 10, 9, 0, 0, tzinfo=UTC)) is True
        assert cron.matches(datetime(2026, 5, 10, 17, 0, 0, tzinfo=UTC)) is True
        assert cron.matches(datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC)) is False


# === CronExpression.next_occurrence ===========================================


class TestCronExpressionNextOccurrence:
    """Verify that next_occurrence() returns the correct future time."""

    def test_next_daily_0200(self) -> None:
        cron = CronExpression("0 2 * * *")
        from_dt = datetime(2026, 5, 10, 1, 59, 0, tzinfo=UTC)
        nxt = cron.next_occurrence(from_dt)
        assert nxt == datetime(2026, 5, 10, 2, 0, 0, tzinfo=UTC)

    def test_next_daily_0200_after_0200(self) -> None:
        cron = CronExpression("0 2 * * *")
        from_dt = datetime(2026, 5, 10, 2, 0, 0, tzinfo=UTC)
        nxt = cron.next_occurrence(from_dt)
        # Should be the *next* day since from_dt is exactly on the match.
        assert nxt == datetime(2026, 5, 11, 2, 0, 0, tzinfo=UTC)

    def test_next_crosses_month(self) -> None:
        cron = CronExpression("0 0 1 * *")
        from_dt = datetime(2026, 5, 15, 12, 0, 0, tzinfo=UTC)
        nxt = cron.next_occurrence(from_dt)
        assert nxt == datetime(2026, 6, 1, 0, 0, 0, tzinfo=UTC)

    def test_next_crosses_year(self) -> None:
        cron = CronExpression("0 0 1 1 *")
        from_dt = datetime(2026, 12, 31, 23, 59, 0, tzinfo=UTC)
        nxt = cron.next_occurrence(from_dt)
        assert nxt == datetime(2027, 1, 1, 0, 0, 0, tzinfo=UTC)

    def test_next_every_5_minutes(self) -> None:
        cron = CronExpression("*/5 * * * *")
        from_dt = datetime(2026, 5, 10, 14, 2, 0, tzinfo=UTC)
        nxt = cron.next_occurrence(from_dt)
        assert nxt == datetime(2026, 5, 10, 14, 5, 0, tzinfo=UTC)


# === Schedule CRUD ============================================================


class TestScheduleCRUD:
    """Verify add, remove, get, and list operations."""

    def _make_scheduler(self) -> RunScheduler:
        return RunScheduler(on_run_trigger=AsyncMock())

    def test_add_schedule_creates_entry(self) -> None:
        sched = self._make_scheduler()
        entry = sched.add_schedule(
            tenant_id=TENANT_A,
            cron_expression="0 2 * * *",
            collector_ids=["whois", "dns"],
            seeds=[{"type": "domain", "value": "example.com"}],
        )
        assert isinstance(entry, ScheduleEntry)
        assert entry.tenant_id == TENANT_A
        assert entry.cron_expression == "0 2 * * *"
        assert entry.collector_ids == ["whois", "dns"]
        assert entry.enabled is True
        assert entry.next_run_at is not None

    def test_add_schedule_replaces_existing(self) -> None:
        sched = self._make_scheduler()
        sched.add_schedule(
            tenant_id=TENANT_A,
            cron_expression="0 2 * * *",
            collector_ids=["whois"],
            seeds=[],
        )
        entry = sched.add_schedule(
            tenant_id=TENANT_A,
            cron_expression="0 3 * * *",
            collector_ids=["dns"],
            seeds=[],
        )
        assert entry.cron_expression == "0 3 * * *"
        assert sched.get_schedule(TENANT_A) is entry
        assert len(sched.list_schedules()) == 1

    def test_remove_schedule_returns_true(self) -> None:
        sched = self._make_scheduler()
        sched.add_schedule(TENANT_A, "0 2 * * *", [], [])
        assert sched.remove_schedule(TENANT_A) is True
        assert sched.get_schedule(TENANT_A) is None

    def test_remove_schedule_returns_false_for_unknown(self) -> None:
        sched = self._make_scheduler()
        assert sched.remove_schedule(TENANT_A) is False

    def test_get_schedule_returns_none_for_unknown(self) -> None:
        sched = self._make_scheduler()
        assert sched.get_schedule(TENANT_A) is None

    def test_list_schedules_returns_all(self) -> None:
        sched = self._make_scheduler()
        sched.add_schedule(TENANT_A, "0 2 * * *", [], [])
        sched.add_schedule(TENANT_B, "0 3 * * *", [], [])
        entries = sched.list_schedules()
        assert len(entries) == 2
        tenant_ids = {e.tenant_id for e in entries}
        assert tenant_ids == {TENANT_A, TENANT_B}

    def test_add_invalid_cron_raises_valueerror(self) -> None:
        sched = self._make_scheduler()
        with pytest.raises(ValueError):
            sched.add_schedule(TENANT_A, "invalid", [], [])


# === Run loop =================================================================


class TestRunLoop:
    """Verify the scheduler loop triggers callbacks correctly."""

    async def test_triggers_callback_at_correct_time(self) -> None:
        callback = AsyncMock()
        sched = RunScheduler(on_run_trigger=callback)

        # Freeze "now" to a specific time so we can control when schedules fire.
        fixed_now = datetime(2026, 5, 10, 2, 0, 30, tzinfo=UTC)

        with patch("expose.pipeline.scheduler.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_now
            mock_dt.side_effect = datetime

            sched.add_schedule(
                tenant_id=TENANT_A,
                cron_expression="0 2 * * *",
                collector_ids=["whois"],
                seeds=[{"type": "domain", "value": "example.com"}],
            )

        # Set next_run_at to be in the past so it fires immediately.
        past_time = datetime(2026, 5, 10, 2, 0, 0, tzinfo=UTC)
        entry = sched.get_schedule(TENANT_A)
        assert entry is not None
        sched._schedules[TENANT_A] = entry.model_copy(
            update={"next_run_at": past_time},
        )

        shutdown = asyncio.Event()

        async def stop_after_one_check() -> None:
            # Give the loop one iteration then stop.
            await asyncio.sleep(0.05)
            shutdown.set()

        with patch("expose.pipeline.scheduler._CHECK_INTERVAL_SECONDS", 0.01):
            await asyncio.gather(
                sched.run(shutdown),
                stop_after_one_check(),
            )

        callback.assert_called_once_with(
            TENANT_A,
            ["whois"],
            [{"type": "domain", "value": "example.com"}],
        )

        # Verify next_run_at was advanced.
        updated = sched.get_schedule(TENANT_A)
        assert updated is not None
        assert updated.last_run_at is not None
        assert updated.next_run_at is not None
        assert updated.next_run_at > past_time

    async def test_disabled_schedule_is_skipped(self) -> None:
        callback = AsyncMock()
        sched = RunScheduler(on_run_trigger=callback)

        sched.add_schedule(TENANT_A, "0 2 * * *", ["whois"], [])

        # Manually disable the schedule and set next_run_at in the past.
        entry = sched.get_schedule(TENANT_A)
        assert entry is not None
        sched._schedules[TENANT_A] = entry.model_copy(
            update={
                "enabled": False,
                "next_run_at": datetime(2026, 5, 10, 2, 0, 0, tzinfo=UTC),
            },
        )

        shutdown = asyncio.Event()

        async def stop_soon() -> None:
            await asyncio.sleep(0.05)
            shutdown.set()

        with patch("expose.pipeline.scheduler._CHECK_INTERVAL_SECONDS", 0.01):
            await asyncio.gather(
                sched.run(shutdown),
                stop_soon(),
            )

        callback.assert_not_called()

    async def test_callback_exception_does_not_crash_loop(self) -> None:
        callback = AsyncMock(side_effect=RuntimeError("boom"))
        sched = RunScheduler(on_run_trigger=callback)

        sched.add_schedule(TENANT_A, "0 2 * * *", ["whois"], [])

        # Force next_run_at into the past.
        entry = sched.get_schedule(TENANT_A)
        assert entry is not None
        sched._schedules[TENANT_A] = entry.model_copy(
            update={"next_run_at": datetime(2026, 5, 10, 2, 0, 0, tzinfo=UTC)},
        )

        shutdown = asyncio.Event()

        async def stop_soon() -> None:
            await asyncio.sleep(0.05)
            shutdown.set()

        with patch("expose.pipeline.scheduler._CHECK_INTERVAL_SECONDS", 0.01):
            # Should NOT raise — the scheduler catches and logs exceptions.
            await asyncio.gather(
                sched.run(shutdown),
                stop_soon(),
            )

        callback.assert_called_once()

        # Schedule should still have advanced next_run_at despite failure.
        updated = sched.get_schedule(TENANT_A)
        assert updated is not None
        assert updated.last_run_at is not None
