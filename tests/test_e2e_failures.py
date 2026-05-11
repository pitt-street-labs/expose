"""End-to-end failure and recovery tests for the EXPOSE pipeline.

Exercises error paths that ``test_e2e_smoke.py`` does not cover:

1. **Collector timeout (partial)** -- ct-crtsh times out, rdap-whois succeeds.
2. **HTTP 500 (partial)** -- ct-crtsh returns server error, rdap-whois succeeds.
3. **All collectors fail** -- both collectors raise ConnectError, run fails.
4. **Quota exceeded** -- pre-flight quota check rejects the run.
5. **Tier-3 denied dispatch** -- active-http-fingerprint denied by empty scope.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import httpx
import pytest
import respx

from expose.collectors.base import Seed, SeedType
from expose.collectors.builtin.active_http import ActiveHttpCollector
from expose.collectors.builtin.ct_crtsh import CrtShCollector
from expose.collectors.builtin.rdap_whois import RdapWhoisCollector
from expose.collectors.registry import CollectorRegistry
from expose.collectors.tiers import TenantAuthorizationScope
from expose.pipeline.dispatcher import DispatchJob, DispatchStatus, PipelineDispatcher
from expose.pipeline.run_executor import RunExecutor
from expose.quotas import QuotaTracker, TenantQuota

# === Deterministic synthetic IDs (UUIDv7-style, greppable) ====================

TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000f001")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000f002")

# === Mock HTTP response bodies ================================================

# Minimal valid RDAP domain response (reused from smoke tests).
RDAP_DOMAIN_RESPONSE = json.dumps({
    "objectClassName": "domain",
    "ldhName": "example.com",
    "status": ["client delete prohibited", "client transfer prohibited"],
    "entities": [
        {
            "objectClassName": "entity",
            "handle": "IANA",
            "roles": ["registrant"],
            "vcardArray": [
                "vcard",
                [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "Internet Assigned Numbers Authority"],
                    ["org", {}, "text", "Internet Assigned Numbers Authority"],
                ],
            ],
        },
    ],
    "events": [
        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2025-08-13T04:00:00Z"},
    ],
    "nameservers": [
        {"objectClassName": "nameserver", "ldhName": "a.iana-servers.net"},
    ],
    "port43": "whois.verisign-grs.com",
})


# === Helpers ==================================================================


def _make_run_row(state: str = "pending") -> MagicMock:
    """Build a mock Run ORM row in the given state."""
    row = MagicMock()
    row.id = RUN_ID
    row.tenant_id = TENANT_ID
    row.state = state
    return row


def _build_mocks() -> tuple[AsyncMock, AsyncMock]:
    """Build mock run and entity repositories.

    Returns (run_repo_mock, entity_repo_mock).
    """
    run_repo = AsyncMock()
    run_repo.get_by_id = AsyncMock(return_value=_make_run_row("pending"))
    run_repo.update_state = AsyncMock()

    entity_repo = AsyncMock()
    entity_repo.create_or_update = AsyncMock(return_value=MagicMock())

    return run_repo, entity_repo


def _build_registry_tier1() -> CollectorRegistry:
    """Build a registry with the two builtin Tier-1 collectors."""
    reg = CollectorRegistry()
    reg.register(CrtShCollector)
    reg.register(RdapWhoisCollector)
    return reg


def _build_dispatcher(
    registry: CollectorRegistry,
    scope_identifiers: frozenset[str] | None = None,
) -> PipelineDispatcher:
    """Build a PipelineDispatcher with a tenant scope."""
    if scope_identifiers is None:
        scope_identifiers = frozenset({"example.com"})
    scope = TenantAuthorizationScope(
        explicit_entity_identifiers=scope_identifiers,
    )
    return PipelineDispatcher(registry, scope, TENANT_ID)


def _setup_rdap_happy() -> None:
    """Register respx routes for rdap-whois with successful responses."""
    respx.get(url__startswith="https://rdap.org/domain/").mock(
        return_value=httpx.Response(
            200,
            text=RDAP_DOMAIN_RESPONSE,
            headers={"content-type": "application/rdap+json"},
        ),
    )
    respx.head("https://rdap.org/").mock(
        return_value=httpx.Response(200),
    )


def _setup_crtsh_health_pass() -> None:
    """Register respx route for ct-crtsh health check passing."""
    respx.head("https://crt.sh/").mock(
        return_value=httpx.Response(200),
    )


# === Test cases ===============================================================


@pytest.mark.integration
@respx.mock
async def test_collector_timeout_partial() -> None:
    """ct-crtsh times out on data fetch; rdap-whois succeeds.

    The data-fetch GET for ct-crtsh raises ``httpx.ReadTimeout``.
    rdap-whois returns normally. The run completes in "partial" state
    because some dispatches succeeded and some failed.
    """
    # rdap-whois: succeeds normally.
    _setup_rdap_happy()

    # ct-crtsh: health check passes, data fetch times out.
    _setup_crtsh_health_pass()
    respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
        side_effect=httpx.ReadTimeout("timeout"),
    )

    registry = _build_registry_tier1()
    dispatcher = _build_dispatcher(registry)
    run_repo, entity_repo = _build_mocks()

    executor = RunExecutor(
        dispatcher=dispatcher,
        run_repo=run_repo,
        entity_repo=entity_repo,
    )

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.DOMAIN, value="example.com")],
        collector_ids=["ct-crtsh", "rdap-whois"],
    )

    assert result.final_state == "partial"
    assert result.failed_dispatches > 0
    assert result.successful_dispatches > 0


@pytest.mark.integration
@respx.mock
async def test_collector_http_500_partial() -> None:
    """ct-crtsh returns HTTP 500; rdap-whois succeeds.

    The data-fetch GET for ct-crtsh returns a 500 Internal Server Error.
    rdap-whois returns normally. The run completes in "partial" state.
    """
    # rdap-whois: succeeds normally.
    _setup_rdap_happy()

    # ct-crtsh: health check passes, data fetch returns 500.
    _setup_crtsh_health_pass()
    respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
        return_value=httpx.Response(500, text="Internal Server Error"),
    )

    registry = _build_registry_tier1()
    dispatcher = _build_dispatcher(registry)
    run_repo, entity_repo = _build_mocks()

    executor = RunExecutor(
        dispatcher=dispatcher,
        run_repo=run_repo,
        entity_repo=entity_repo,
    )

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.DOMAIN, value="example.com")],
        collector_ids=["ct-crtsh", "rdap-whois"],
    )

    assert result.final_state == "partial"
    assert result.failed_dispatches > 0
    assert result.successful_dispatches > 0


@pytest.mark.integration
@respx.mock
async def test_all_collectors_fail() -> None:
    """Both ct-crtsh and rdap-whois fail with ConnectError.

    Every dispatch fails, so the run completes in "failed" state with
    zero successful dispatches.
    """
    # ct-crtsh: health check passes, data fetch fails.
    _setup_crtsh_health_pass()
    respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
        side_effect=httpx.ConnectError("connection refused"),
    )

    # rdap-whois: health check passes, data fetch fails.
    respx.head("https://rdap.org/").mock(
        return_value=httpx.Response(200),
    )
    respx.get(url__startswith="https://rdap.org/domain/").mock(
        side_effect=httpx.ConnectError("connection refused"),
    )

    registry = _build_registry_tier1()
    dispatcher = _build_dispatcher(registry)
    run_repo, entity_repo = _build_mocks()

    executor = RunExecutor(
        dispatcher=dispatcher,
        run_repo=run_repo,
        entity_repo=entity_repo,
    )

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.DOMAIN, value="example.com")],
        collector_ids=["ct-crtsh", "rdap-whois"],
    )

    assert result.final_state == "failed"
    assert result.successful_dispatches == 0
    assert result.failed_dispatches > 0


@pytest.mark.integration
@respx.mock
async def test_quota_exceeded_fails_run() -> None:
    """QuotaTracker rejects the run before any dispatches execute.

    A TenantQuota with max_runs_per_day=1 is set, then one run is
    recorded to exhaust the quota. The executor should detect the
    quota violation in its pre-flight check and return final_state="failed"
    with zero dispatches.
    """
    # Set up happy routes (should never be reached, but register defensively).
    _setup_rdap_happy()
    _setup_crtsh_health_pass()
    respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
        return_value=httpx.Response(200, text="[]"),
    )

    registry = _build_registry_tier1()
    dispatcher = _build_dispatcher(registry)
    run_repo, entity_repo = _build_mocks()

    # Create a quota tracker with a 1-run-per-day limit and exhaust it.
    tracker = QuotaTracker()
    tracker.set_quota(TenantQuota(tenant_id=TENANT_ID, max_runs_per_day=1))
    tracker.record_run_start(TENANT_ID)

    executor = RunExecutor(
        dispatcher=dispatcher,
        run_repo=run_repo,
        entity_repo=entity_repo,
        quota_tracker=tracker,
    )

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.DOMAIN, value="example.com")],
        collector_ids=["ct-crtsh", "rdap-whois"],
    )

    assert result.final_state == "failed"
    assert result.total_dispatches == 0
    assert result.successful_dispatches == 0
    assert result.failed_dispatches == 0


@pytest.mark.integration
@respx.mock
async def test_tier3_denied_dispatch() -> None:
    """Tier-3 collector dispatch denied by empty authorization scope.

    ActiveHttpCollector is Tier 3. When the tenant scope contains no
    explicit entity identifiers, the dispatcher must deny the dispatch
    before any HTTP calls are made.
    """
    # Mock health-check and data-fetch URLs defensively; the denial should
    # happen before they are reached.
    respx.head("https://httpbin.org/head").mock(
        return_value=httpx.Response(200),
    )
    respx.get(url__startswith="https://example.com").mock(
        return_value=httpx.Response(200, text="<html></html>"),
    )
    respx.get(url__startswith="http://example.com").mock(
        return_value=httpx.Response(200, text="<html></html>"),
    )

    registry = CollectorRegistry()
    registry.register(ActiveHttpCollector)

    # Empty scope -- no entity identifiers authorized.
    dispatcher = _build_dispatcher(registry, scope_identifiers=frozenset())

    job = DispatchJob(
        collector_id="active-http-fingerprint",
        seed=Seed(seed_type=SeedType.DOMAIN, value="example.com"),
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
    )

    result = await dispatcher.dispatch(job)

    assert result.status == DispatchStatus.DENIED
    assert result.error_message is not None
    assert len(result.observations) == 0
