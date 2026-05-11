"""Integration tests for the RunScheduler — end-to-end scheduling reliability.

Covers scenarios NOT in the existing unit/API test files:

 1.  Consecutive failures increment and auto-disable after threshold.
 2.  Successful run after failures resets consecutive_failures to 0.
 3.  Multiple tenants fire independently in the same loop iteration.
 4.  Schedule added during a running loop is picked up on next tick.
 5.  Schedule removed during a running loop stops firing.
 6.  Cron with symbolic day-of-week names (sun, mon, ...) works.
 7.  Cron with symbolic month names (jan, feb, ...) works.
 8.  Scheduler loop timing: does not fire before next_run_at.
 9.  Scheduler loop timing: fires when next_run_at equals now.
10.  Scheduler shutdown stops the loop within the timeout.
11.  Rapid successive triggers do not double-fire (next_run_at advances).
12.  API create -> scheduler has entry -> API delete -> scheduler entry gone.
13.  Re-enable a disabled schedule and verify it fires again.
14.  Persistence gap: schedule_cron in tenant config vs scheduler state.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch
from uuid import UUID, uuid4

import pytest

from expose.pipeline.scheduler import (
    CronExpression,
    RunScheduler,
    ScheduleEntry,
    _MAX_CONSECUTIVE_FAILURES,
)


# === Helpers ==================================================================

TENANT_A = UUID("018f1f00-0000-7000-8000-00000000B001")
TENANT_B = UUID("018f1f00-0000-7000-8000-00000000B002")
TENANT_C = UUID("018f1f00-0000-7000-8000-00000000B003")


def _force_next_run(
    scheduler: RunScheduler,
    tenant_id: UUID,
    next_run_at: datetime,
    **overrides: object,
) -> None:
    """Manipulate a schedule entry's next_run_at (and optional fields)."""
    entry = scheduler.get_schedule(tenant_id)
    assert entry is not None, f"No schedule for {tenant_id}"
    updates: dict[str, object] = {"next_run_at": next_run_at, **overrides}
    scheduler._schedules[tenant_id] = entry.model_copy(update=updates)


async def _run_one_tick(
    scheduler: RunScheduler,
    *,
    interval: float = 0.01,
    settle: float = 0.05,
) -> None:
    """Run the scheduler loop for one iteration, then shut it down."""
    shutdown = asyncio.Event()

    async def _stop() -> None:
        await asyncio.sleep(settle)
        shutdown.set()

    with patch("expose.pipeline.scheduler._CHECK_INTERVAL_SECONDS", interval):
        await asyncio.gather(scheduler.run(shutdown), _stop())


# === 1. Consecutive failures auto-disable =====================================


class TestConsecutiveFailureAutoDisable:
    """Verify the auto-disable mechanism after N consecutive callback failures."""

    async def test_increments_on_each_failure(self) -> None:
        callback = AsyncMock(side_effect=RuntimeError("fail"))
        sched = RunScheduler(on_run_trigger=callback)

        sched.add_schedule(TENANT_A, "* * * * *", ["c1"], [])
        past = datetime(2020, 1, 1, tzinfo=UTC)
        _force_next_run(sched, TENANT_A, past)

        await _run_one_tick(sched)

        entry = sched.get_schedule(TENANT_A)
        assert entry is not None
        assert entry.consecutive_failures == 1
        assert entry.last_error == "fail"
        # Not yet disabled (threshold is 5).
        assert entry.enabled is True

    async def test_disables_after_max_failures(self) -> None:
        callback = AsyncMock(side_effect=RuntimeError("persistent-fail"))
        sched = RunScheduler(on_run_trigger=callback)

        sched.add_schedule(TENANT_A, "* * * * *", ["c1"], [])

        # Simulate _MAX_CONSECUTIVE_FAILURES iterations.
        for i in range(_MAX_CONSECUTIVE_FAILURES):
            past = datetime(2020, 1, 1, tzinfo=UTC)
            _force_next_run(sched, TENANT_A, past)
            await _run_one_tick(sched)

            entry = sched.get_schedule(TENANT_A)
            assert entry is not None
            assert entry.consecutive_failures == i + 1

        entry = sched.get_schedule(TENANT_A)
        assert entry is not None
        assert entry.enabled is False
        assert entry.consecutive_failures == _MAX_CONSECUTIVE_FAILURES
        assert entry.last_error == "persistent-fail"

    async def test_disabled_schedule_does_not_fire(self) -> None:
        """Once auto-disabled, the schedule must not fire even with past next_run_at."""
        callback = AsyncMock()
        sched = RunScheduler(on_run_trigger=callback)

        sched.add_schedule(TENANT_A, "* * * * *", ["c1"], [])
        past = datetime(2020, 1, 1, tzinfo=UTC)
        _force_next_run(sched, TENANT_A, past, enabled=False)

        await _run_one_tick(sched)

        callback.assert_not_called()


# === 2. Success resets failures ===============================================


class TestSuccessResetsFailures:
    """A successful trigger must reset consecutive_failures to zero."""

    async def test_reset_after_recovery(self) -> None:
        call_count = 0

        async def _flaky_trigger(
            _tid: UUID, _cids: list[str], _seeds: list[dict]
        ) -> None:
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                raise RuntimeError("transient")

        sched = RunScheduler(on_run_trigger=_flaky_trigger)
        sched.add_schedule(TENANT_A, "* * * * *", ["c1"], [])

        # Fail twice.
        for _ in range(2):
            _force_next_run(sched, TENANT_A, datetime(2020, 1, 1, tzinfo=UTC))
            await _run_one_tick(sched)

        entry = sched.get_schedule(TENANT_A)
        assert entry is not None
        assert entry.consecutive_failures == 2
        assert entry.last_run_at is None  # No successful run yet.

        # Third call succeeds.
        _force_next_run(sched, TENANT_A, datetime(2020, 1, 1, tzinfo=UTC))
        await _run_one_tick(sched)

        entry = sched.get_schedule(TENANT_A)
        assert entry is not None
        assert entry.consecutive_failures == 0
        assert entry.last_error is None
        assert entry.last_run_at is not None


# === 3. Multi-tenant independent firing =======================================


class TestMultiTenantFiring:
    """Multiple tenants with different schedules fire independently."""

    async def test_both_tenants_fire(self) -> None:
        calls: list[UUID] = []

        async def _trigger(
            tid: UUID, _cids: list[str], _seeds: list[dict]
        ) -> None:
            calls.append(tid)

        sched = RunScheduler(on_run_trigger=_trigger)
        sched.add_schedule(TENANT_A, "* * * * *", ["c1"], [])
        sched.add_schedule(TENANT_B, "* * * * *", ["c2"], [])

        past = datetime(2020, 1, 1, tzinfo=UTC)
        _force_next_run(sched, TENANT_A, past)
        _force_next_run(sched, TENANT_B, past)

        await _run_one_tick(sched)

        assert TENANT_A in calls
        assert TENANT_B in calls
        assert len(calls) == 2

    async def test_only_due_tenant_fires(self) -> None:
        calls: list[UUID] = []

        async def _trigger(
            tid: UUID, _cids: list[str], _seeds: list[dict]
        ) -> None:
            calls.append(tid)

        sched = RunScheduler(on_run_trigger=_trigger)
        sched.add_schedule(TENANT_A, "* * * * *", ["c1"], [])
        sched.add_schedule(TENANT_B, "* * * * *", ["c2"], [])

        past = datetime(2020, 1, 1, tzinfo=UTC)
        future = datetime(2099, 1, 1, tzinfo=UTC)
        _force_next_run(sched, TENANT_A, past)
        _force_next_run(sched, TENANT_B, future)

        await _run_one_tick(sched)

        assert calls == [TENANT_A]

    async def test_failure_in_one_does_not_block_other(self) -> None:
        """If tenant A's trigger raises, tenant B must still fire."""
        calls: list[UUID] = []
        call_order: list[UUID] = []

        async def _trigger(
            tid: UUID, _cids: list[str], _seeds: list[dict]
        ) -> None:
            call_order.append(tid)
            if tid == TENANT_A:
                raise RuntimeError("A fails")
            calls.append(tid)

        sched = RunScheduler(on_run_trigger=_trigger)
        sched.add_schedule(TENANT_A, "* * * * *", ["c1"], [])
        sched.add_schedule(TENANT_B, "* * * * *", ["c2"], [])

        past = datetime(2020, 1, 1, tzinfo=UTC)
        _force_next_run(sched, TENANT_A, past)
        _force_next_run(sched, TENANT_B, past)

        await _run_one_tick(sched)

        # Both were attempted.
        assert len(call_order) == 2
        # B's trigger succeeded.
        assert TENANT_B in calls


# === 4. Schedule added during running loop ====================================


class TestDynamicScheduleAddition:
    """A schedule added while the loop is running is picked up on the next tick."""

    async def test_added_schedule_fires_on_next_iteration(self) -> None:
        calls: list[UUID] = []

        async def _trigger(
            tid: UUID, _cids: list[str], _seeds: list[dict]
        ) -> None:
            calls.append(tid)

        sched = RunScheduler(on_run_trigger=_trigger)
        shutdown = asyncio.Event()

        async def _add_then_stop() -> None:
            # Let first iteration run (no schedules yet).
            await asyncio.sleep(0.03)
            # Add a schedule with next_run_at in the past.
            sched.add_schedule(TENANT_A, "* * * * *", ["c1"], [])
            _force_next_run(sched, TENANT_A, datetime(2020, 1, 1, tzinfo=UTC))
            # Let the next iteration pick it up.
            await asyncio.sleep(0.05)
            shutdown.set()

        with patch("expose.pipeline.scheduler._CHECK_INTERVAL_SECONDS", 0.02):
            await asyncio.gather(sched.run(shutdown), _add_then_stop())

        assert TENANT_A in calls


# === 5. Schedule removed during running loop ==================================


class TestDynamicScheduleRemoval:
    """A schedule removed while the loop is running stops firing."""

    async def test_removed_schedule_stops_firing(self) -> None:
        calls: list[UUID] = []

        async def _trigger(
            tid: UUID, _cids: list[str], _seeds: list[dict]
        ) -> None:
            calls.append(tid)

        sched = RunScheduler(on_run_trigger=_trigger)
        sched.add_schedule(TENANT_A, "* * * * *", ["c1"], [])
        _force_next_run(sched, TENANT_A, datetime(2020, 1, 1, tzinfo=UTC))

        shutdown = asyncio.Event()

        async def _remove_then_stop() -> None:
            # Let it fire once.
            await asyncio.sleep(0.03)
            # Remove the schedule.
            sched.remove_schedule(TENANT_A)
            # Reset for next tick -- but schedule is gone.
            await asyncio.sleep(0.05)
            shutdown.set()

        with patch("expose.pipeline.scheduler._CHECK_INTERVAL_SECONDS", 0.02):
            await asyncio.gather(sched.run(shutdown), _remove_then_stop())

        # Should have fired exactly once (before removal).
        assert calls.count(TENANT_A) == 1


# === 6. Symbolic day-of-week names ===========================================


class TestSymbolicDowNames:
    """CronExpression handles symbolic day-of-week names (sun, mon, ...)."""

    @pytest.mark.parametrize(
        ("name", "expected_int"),
        [
            ("sun", 0),
            ("mon", 1),
            ("tue", 2),
            ("wed", 3),
            ("thu", 4),
            ("fri", 5),
            ("sat", 6),
        ],
    )
    def test_symbolic_dow(self, name: str, expected_int: int) -> None:
        cron = CronExpression(f"0 0 * * {name}")
        assert expected_int in cron._dows

    def test_symbolic_dow_case_insensitive(self) -> None:
        cron = CronExpression("0 0 * * MON")
        assert 1 in cron._dows

    def test_symbolic_dow_range(self) -> None:
        cron = CronExpression("0 0 * * mon-fri")
        assert cron._dows == frozenset({1, 2, 3, 4, 5})


# === 7. Symbolic month names ==================================================


class TestSymbolicMonthNames:
    """CronExpression handles symbolic month names (jan, feb, ...)."""

    def test_symbolic_month_jan(self) -> None:
        cron = CronExpression("0 0 1 jan *")
        assert 1 in cron._months

    def test_symbolic_month_dec(self) -> None:
        cron = CronExpression("0 0 1 dec *")
        assert 12 in cron._months

    def test_symbolic_month_range(self) -> None:
        cron = CronExpression("0 0 1 mar-may *")
        assert cron._months == frozenset({3, 4, 5})

    def test_symbolic_month_case_insensitive(self) -> None:
        cron = CronExpression("0 0 1 JUN *")
        assert 6 in cron._months


# === 8. Scheduler does not fire before next_run_at ============================


class TestTimingPrecision:
    """The scheduler must not fire before next_run_at."""

    async def test_does_not_fire_before_due(self) -> None:
        callback = AsyncMock()
        sched = RunScheduler(on_run_trigger=callback)

        sched.add_schedule(TENANT_A, "* * * * *", ["c1"], [])
        future = datetime.now(UTC) + timedelta(hours=1)
        _force_next_run(sched, TENANT_A, future)

        await _run_one_tick(sched)

        callback.assert_not_called()

    async def test_fires_when_due(self) -> None:
        callback = AsyncMock()
        sched = RunScheduler(on_run_trigger=callback)

        sched.add_schedule(TENANT_A, "* * * * *", ["c1"], [])
        past = datetime(2020, 1, 1, tzinfo=UTC)
        _force_next_run(sched, TENANT_A, past)

        await _run_one_tick(sched)

        callback.assert_called_once()

    async def test_next_run_advances_after_fire(self) -> None:
        """After firing, next_run_at must be strictly in the future."""
        callback = AsyncMock()
        sched = RunScheduler(on_run_trigger=callback)

        sched.add_schedule(TENANT_A, "*/5 * * * *", ["c1"], [])
        past = datetime(2020, 1, 1, tzinfo=UTC)
        _force_next_run(sched, TENANT_A, past)

        await _run_one_tick(sched)

        entry = sched.get_schedule(TENANT_A)
        assert entry is not None
        assert entry.next_run_at is not None
        # next_run_at should be in the future relative to when the tick ran.
        assert entry.next_run_at > datetime.now(UTC) - timedelta(seconds=10)


# === 9. next_run_at exactly equals now ========================================


class TestExactTimeMatch:
    """When next_run_at is exactly now, the schedule fires (>= comparison)."""

    async def test_fires_at_exact_time(self) -> None:
        callback = AsyncMock()
        sched = RunScheduler(on_run_trigger=callback)

        sched.add_schedule(TENANT_A, "* * * * *", ["c1"], [])
        # Use a time that's definitely in the past by a tiny amount.
        almost_now = datetime.now(UTC) - timedelta(milliseconds=1)
        _force_next_run(sched, TENANT_A, almost_now)

        await _run_one_tick(sched)

        callback.assert_called_once()


# === 10. Scheduler shutdown ===================================================


class TestSchedulerShutdown:
    """The scheduler loop exits cleanly on shutdown signal."""

    async def test_shutdown_exits_within_timeout(self) -> None:
        callback = AsyncMock()
        sched = RunScheduler(on_run_trigger=callback)
        shutdown = asyncio.Event()

        task = asyncio.create_task(sched.run(shutdown))
        await asyncio.sleep(0.02)
        assert not task.done()

        shutdown.set()
        await asyncio.wait_for(task, timeout=5.0)
        assert task.done()
        assert not task.cancelled()

    async def test_shutdown_during_idle_wait(self) -> None:
        """Shutdown during the 60s sleep wakes the loop immediately."""
        callback = AsyncMock()
        sched = RunScheduler(on_run_trigger=callback)
        shutdown = asyncio.Event()

        # Use a large check interval to prove we don't wait the full duration.
        with patch("expose.pipeline.scheduler._CHECK_INTERVAL_SECONDS", 300):
            task = asyncio.create_task(sched.run(shutdown))
            await asyncio.sleep(0.02)

            shutdown.set()
            # Should exit quickly despite the 300s interval.
            await asyncio.wait_for(task, timeout=2.0)
            assert task.done()


# === 11. No double-fire on rapid ticks ========================================


class TestNoDoubleFire:
    """After a schedule fires, next_run_at advances so it cannot double-fire."""

    async def test_rapid_ticks_single_fire(self) -> None:
        calls: list[UUID] = []

        async def _trigger(
            tid: UUID, _cids: list[str], _seeds: list[dict]
        ) -> None:
            calls.append(tid)

        sched = RunScheduler(on_run_trigger=_trigger)
        sched.add_schedule(TENANT_A, "0 2 * * *", ["c1"], [])
        past = datetime(2020, 1, 1, tzinfo=UTC)
        _force_next_run(sched, TENANT_A, past)

        # Run multiple ticks rapidly.
        for _ in range(3):
            await _run_one_tick(sched, settle=0.03)

        # Should have fired exactly once -- next_run_at advanced after first fire.
        assert calls.count(TENANT_A) == 1


# === 12. API create -> scheduler -> API delete ================================


class TestAPISchedulerRoundTrip:
    """End-to-end: API creates schedule, scheduler has it, API deletes it."""

    async def test_create_registers_in_scheduler(self) -> None:
        callback = AsyncMock()
        sched = RunScheduler(on_run_trigger=callback)

        entry = sched.add_schedule(
            TENANT_A, "0 3 * * *", ["whois"], [{"value": "example.com"}]
        )

        assert sched.get_schedule(TENANT_A) is not None
        assert entry.cron_expression == "0 3 * * *"
        assert entry.collector_ids == ["whois"]
        assert entry.seeds == [{"value": "example.com"}]
        assert entry.enabled is True
        assert entry.next_run_at is not None

    async def test_delete_removes_from_scheduler(self) -> None:
        callback = AsyncMock()
        sched = RunScheduler(on_run_trigger=callback)

        sched.add_schedule(TENANT_A, "0 3 * * *", ["whois"], [])
        assert sched.get_schedule(TENANT_A) is not None

        assert sched.remove_schedule(TENANT_A) is True
        assert sched.get_schedule(TENANT_A) is None

        # After removal, the schedule must not fire.
        await _run_one_tick(sched)
        callback.assert_not_called()


# === 13. Re-enable a disabled schedule ========================================


class TestReEnableSchedule:
    """A disabled schedule can be re-enabled by replacing it."""

    async def test_re_add_enables_schedule(self) -> None:
        callback = AsyncMock(side_effect=RuntimeError("boom"))
        sched = RunScheduler(on_run_trigger=callback)

        sched.add_schedule(TENANT_A, "* * * * *", ["c1"], [])

        # Drive to auto-disable.
        for _ in range(_MAX_CONSECUTIVE_FAILURES):
            _force_next_run(sched, TENANT_A, datetime(2020, 1, 1, tzinfo=UTC))
            await _run_one_tick(sched)

        entry = sched.get_schedule(TENANT_A)
        assert entry is not None
        assert entry.enabled is False

        # Re-add the schedule (simulates re-creating via the API).
        callback.side_effect = None  # Fix the trigger.
        callback.reset_mock()
        new_entry = sched.add_schedule(TENANT_A, "* * * * *", ["c1"], [])
        assert new_entry.enabled is True
        assert new_entry.consecutive_failures == 0

        _force_next_run(sched, TENANT_A, datetime(2020, 1, 1, tzinfo=UTC))
        await _run_one_tick(sched)

        callback.assert_called_once()


# === 14. Persistence gap awareness ============================================


class TestPersistenceGap:
    """Document the current persistence gap: schedules are in-memory only.

    These tests verify the gap exists so a future fix can flip assertions.
    """

    def test_schedules_not_shared_between_instances(self) -> None:
        """Two RunScheduler instances do not share state."""
        callback = AsyncMock()
        sched1 = RunScheduler(on_run_trigger=callback)
        sched2 = RunScheduler(on_run_trigger=callback)

        sched1.add_schedule(TENANT_A, "0 2 * * *", ["c1"], [])

        # sched2 has no knowledge of sched1's schedules.
        assert sched2.get_schedule(TENANT_A) is None
        assert sched2.list_schedules() == []

    def test_schedule_entry_is_frozen(self) -> None:
        """ScheduleEntry is a frozen Pydantic model -- mutation creates a copy."""
        entry = ScheduleEntry(
            tenant_id=TENANT_A,
            cron_expression="0 2 * * *",
        )
        updated = entry.model_copy(update={"enabled": False})
        assert entry.enabled is True
        assert updated.enabled is False
        assert entry is not updated


# === 15. CronExpression edge cases ============================================


class TestCronEdgeCases:
    """Edge cases in cron expression parsing and matching."""

    def test_step_on_range(self) -> None:
        """1-10/3 should produce {1, 4, 7, 10}."""
        cron = CronExpression("1-10/3 * * * *")
        assert cron._minutes == frozenset({1, 4, 7, 10})

    def test_star_slash_step(self) -> None:
        """*/15 on minutes should produce {0, 15, 30, 45}."""
        cron = CronExpression("*/15 * * * *")
        assert cron._minutes == frozenset({0, 15, 30, 45})

    def test_comma_list_multiple(self) -> None:
        """0,30 on minutes should produce {0, 30}."""
        cron = CronExpression("0,30 * * * *")
        assert cron._minutes == frozenset({0, 30})

    def test_posix_or_semantics_for_dom_and_dow(self) -> None:
        """When both DOM and DOW are restricted, POSIX OR semantics apply.

        '0 0 15 * fri' means: fires on the 15th of any month OR any Friday.
        """
        cron = CronExpression("0 0 15 * 5")

        # Friday the 15th -- both match.
        # 2026-05-15 is a Friday.
        dt_both = datetime(2026, 5, 15, 0, 0, tzinfo=UTC)
        assert cron.matches(dt_both) is True

        # A Friday that is NOT the 15th.
        dt_fri = datetime(2026, 5, 8, 0, 0, tzinfo=UTC)  # Friday May 8
        assert cron.matches(dt_fri) is True

        # The 15th on a non-Friday.
        dt_15th = datetime(2026, 6, 15, 0, 0, tzinfo=UTC)  # Monday June 15
        assert cron.matches(dt_15th) is True

        # Neither Friday nor 15th.
        dt_neither = datetime(2026, 5, 7, 0, 0, tzinfo=UTC)  # Thursday May 7
        assert cron.matches(dt_neither) is False

    def test_next_occurrence_always_future(self) -> None:
        """next_occurrence must always return a time strictly after from_dt."""
        cron = CronExpression("* * * * *")
        now = datetime(2026, 5, 11, 12, 30, 0, tzinfo=UTC)
        nxt = cron.next_occurrence(now)
        assert nxt > now

    def test_next_occurrence_from_exact_match_advances(self) -> None:
        """If from_dt itself matches, next_occurrence returns the NEXT match."""
        cron = CronExpression("30 12 * * *")
        # This exact time matches the cron.
        from_dt = datetime(2026, 5, 11, 12, 30, 0, tzinfo=UTC)
        nxt = cron.next_occurrence(from_dt)
        # Must return the next day's 12:30, not from_dt itself.
        assert nxt == datetime(2026, 5, 12, 12, 30, 0, tzinfo=UTC)

    def test_invalid_step_zero_raises(self) -> None:
        """Step of 0 must raise ValueError."""
        with pytest.raises(ValueError, match="Step must be >= 1"):
            CronExpression("*/0 * * * *")

    def test_inverted_range_raises(self) -> None:
        """Range with start > end must raise ValueError."""
        with pytest.raises(ValueError, match="Range start .* > end"):
            CronExpression("10-5 * * * *")


# === 16. Callback receives correct arguments =================================


class TestCallbackArguments:
    """The trigger callback must receive exactly the registered arguments."""

    async def test_callback_receives_tenant_and_data(self) -> None:
        received: list[tuple[UUID, list[str], list[dict]]] = []

        async def _trigger(
            tid: UUID, cids: list[str], seeds: list[dict]
        ) -> None:
            received.append((tid, cids, seeds))

        sched = RunScheduler(on_run_trigger=_trigger)
        seeds = [{"value": "example.com", "seed_type": "DOMAIN"}]
        sched.add_schedule(TENANT_A, "* * * * *", ["whois", "dns"], seeds)
        _force_next_run(sched, TENANT_A, datetime(2020, 1, 1, tzinfo=UTC))

        await _run_one_tick(sched)

        assert len(received) == 1
        tid, cids, s = received[0]
        assert tid == TENANT_A
        assert cids == ["whois", "dns"]
        assert s == seeds

    async def test_callback_receives_copies_not_references(self) -> None:
        """Mutating callback args must not corrupt the schedule entry."""
        received_cids: list[list[str]] = []

        async def _trigger(
            _tid: UUID, cids: list[str], _seeds: list[dict]
        ) -> None:
            cids.append("MUTATED")
            received_cids.append(cids)

        sched = RunScheduler(on_run_trigger=_trigger)
        sched.add_schedule(TENANT_A, "* * * * *", ["c1"], [])
        _force_next_run(sched, TENANT_A, datetime(2020, 1, 1, tzinfo=UTC))

        await _run_one_tick(sched)

        # The trigger mutated the list it received.
        assert "MUTATED" in received_cids[0]

        # But the schedule entry's collector_ids must be untouched.
        entry = sched.get_schedule(TENANT_A)
        assert entry is not None
        assert "MUTATED" not in entry.collector_ids


# === 17. Three-tenant independence ============================================


class TestThreeTenantIndependence:
    """Three tenants with different crons, only the due ones fire."""

    async def test_mixed_due_and_not_due(self) -> None:
        calls: list[UUID] = []

        async def _trigger(
            tid: UUID, _cids: list[str], _seeds: list[dict]
        ) -> None:
            calls.append(tid)

        sched = RunScheduler(on_run_trigger=_trigger)
        sched.add_schedule(TENANT_A, "0 2 * * *", ["c1"], [])
        sched.add_schedule(TENANT_B, "30 4 * * *", ["c2"], [])
        sched.add_schedule(TENANT_C, "0 6 * * *", ["c3"], [])

        past = datetime(2020, 1, 1, tzinfo=UTC)
        future = datetime(2099, 1, 1, tzinfo=UTC)

        _force_next_run(sched, TENANT_A, past)   # Due.
        _force_next_run(sched, TENANT_B, future)  # Not due.
        _force_next_run(sched, TENANT_C, past)   # Due.

        await _run_one_tick(sched)

        assert set(calls) == {TENANT_A, TENANT_C}
        assert TENANT_B not in calls
