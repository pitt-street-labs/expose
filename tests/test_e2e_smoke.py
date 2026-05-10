"""End-to-end smoke test: seed -> expand -> dispatch -> collect -> upsert.

Exercises the complete EXPOSE pipeline from ``PipelineDispatcher`` through
``RunExecutor`` with real builtin collectors (``ct-crtsh``, ``rdap-whois``)
but NO live external services. All HTTP traffic is intercepted by ``respx``;
repository layers are ``AsyncMock``-ed.

Three test cases:

1. **Full pipeline smoke** — domain seed dispatched through 2 Tier-1
   collectors, observations collected, graph upsert called, run completed.
2. **Seed expansion integrated** — ``www.example.com`` generated alongside
   ``example.com``, dispatch count reflects expanded seeds.
3. **Partial failure** — one collector mocked to return a network error,
   run state = ``partial``.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import httpx
import pytest
import respx

from expose.collectors.base import Seed, SeedType
from expose.collectors.builtin.ct_crtsh import CrtShCollector
from expose.collectors.builtin.rdap_whois import RdapWhoisCollector
from expose.collectors.registry import CollectorRegistry
from expose.collectors.tiers import TenantAuthorizationScope
from expose.pipeline.dispatcher import PipelineDispatcher
from expose.pipeline.run_executor import RunExecutor

# === Deterministic synthetic IDs (UUIDv7-style, greppable) ====================

TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000e2e1")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000e2e2")


# === Mock HTTP response bodies ================================================

# Minimal valid crt.sh JSON response — two distinct certificates.
CRT_SH_RESPONSE = json.dumps([
    {
        "issuer_ca_id": 16418,
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "common_name": "example.com",
        "name_value": "example.com\nwww.example.com",
        "id": 1111111111,
        "entry_timestamp": "2025-01-15T10:30:00.000",
        "not_before": "2025-01-15T00:00:00",
        "not_after": "2025-04-15T00:00:00",
        "serial_number": "aabb0011223344556677889900aabbcc",
    },
    {
        "issuer_ca_id": 185756,
        "issuer_name": "C=US, O=Amazon, CN=Amazon RSA 2048 M01",
        "common_name": "api.example.com",
        "name_value": "api.example.com",
        "id": 2222222222,
        "entry_timestamp": "2025-02-20T14:45:00.000",
        "not_before": "2025-02-20T00:00:00",
        "not_after": "2025-05-20T00:00:00",
        "serial_number": "ccdd0011223344556677889900aabbee",
    },
])

# Minimal valid RDAP domain response.
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
        {
            "objectClassName": "entity",
            "handle": "376",
            "roles": ["registrar"],
            "vcardArray": [
                "vcard",
                [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "RESERVED-IANA"],
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
        {"objectClassName": "nameserver", "ldhName": "b.iana-servers.net"},
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


def _build_registry() -> CollectorRegistry:
    """Build a fresh registry with the two builtin Tier-1 collectors."""
    reg = CollectorRegistry()
    reg.register(CrtShCollector)
    reg.register(RdapWhoisCollector)
    return reg


def _build_dispatcher(registry: CollectorRegistry) -> PipelineDispatcher:
    """Build a PipelineDispatcher with a tenant scope containing example.com."""
    scope = TenantAuthorizationScope(
        explicit_entity_identifiers=frozenset({"example.com"}),
    )
    return PipelineDispatcher(registry, scope, TENANT_ID)


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


def _setup_respx_routes_happy() -> None:
    """Register respx routes for both collectors with successful responses.

    Also mocks the health-check HEAD requests for both collectors.
    """
    # ct-crtsh: GET https://crt.sh/?q=%.example.com&output=json
    # The collector uses params, respx matches on base URL + partial params.
    respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
        return_value=httpx.Response(200, text=CRT_SH_RESPONSE),
    )
    # ct-crtsh health check: HEAD https://crt.sh/
    respx.head("https://crt.sh/").mock(
        return_value=httpx.Response(200),
    )

    # rdap-whois: GET https://rdap.org/domain/<domain>
    # Matches any domain query under the bootstrap base.
    respx.get(url__startswith="https://rdap.org/domain/").mock(
        return_value=httpx.Response(
            200,
            text=RDAP_DOMAIN_RESPONSE,
            headers={"content-type": "application/rdap+json"},
        ),
    )
    # rdap-whois health check: HEAD https://rdap.org/
    respx.head("https://rdap.org/").mock(
        return_value=httpx.Response(200),
    )


# === Test cases ===============================================================


@pytest.mark.integration
@respx.mock
async def test_e2e_pipeline_smoke() -> None:
    """Smoke test: seed -> expand -> dispatch -> collect -> upsert.

    Full pipeline with domain seed 'example.com' dispatched through ct-crtsh
    and rdap-whois collectors. Verifies:
    - RunResult.final_state is "completed"
    - RunResult.total_observations > 0
    - RunResult.successful_dispatches == 2 (for the original example.com seed)
    - entity_repo.create_or_update was called at least once
    - run_repo.update_state was called with "running" and then "completed"
    """
    _setup_respx_routes_happy()

    registry = _build_registry()
    dispatcher = _build_dispatcher(registry)
    run_repo, entity_repo = _build_mocks()

    executor = RunExecutor(
        dispatcher=dispatcher,
        run_repo=run_repo,
        entity_repo=entity_repo,
    )

    # Use IP seed type so seed expansion does NOT generate www. variant.
    # This lets us assert exactly 2 dispatches (1 seed x 2 collectors).
    # (ct-crtsh skips non-domain seeds, but rdap-whois supports IP.)
    # Actually, both collectors expect domain seeds for full coverage,
    # so we use a domain seed and account for expansion in the assertion.
    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.DOMAIN, value="example.com")],
        collector_ids=["ct-crtsh", "rdap-whois"],
    )

    # Final state must be completed (no failures when all routes return 200).
    assert result.final_state == "completed"

    # Observations should include at least the crt.sh entries + rdap entries.
    assert result.total_observations > 0

    # With seed expansion, example.com -> [example.com, www.example.com].
    # 2 expanded seeds x 2 collectors = 4 dispatches, all successful.
    assert result.successful_dispatches >= 2
    assert result.failed_dispatches == 0

    # Entity repo should have been called for graph upsert.
    assert entity_repo.create_or_update.call_count >= 1

    # Run state machine: pending -> running -> completed.
    state_calls = run_repo.update_state.call_args_list
    assert len(state_calls) == 2
    assert state_calls[0].kwargs["new_state"] == "running"
    assert state_calls[1].kwargs["new_state"] == "completed"


@pytest.mark.integration
@respx.mock
async def test_e2e_seed_expansion_integrated() -> None:
    """Verify seed expansion produces www.example.com alongside example.com.

    The executor should expand a single domain seed into two seeds and
    dispatch each against every enabled collector.
    """
    _setup_respx_routes_happy()

    registry = _build_registry()
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

    # 1 input seed expanded to 2 (example.com + www.example.com).
    assert result.total_seeds == 1
    assert result.expanded_seeds == 2

    # 2 expanded seeds x 2 collectors = 4 total dispatches.
    assert result.total_dispatches == 4
    assert result.successful_dispatches == 4
    assert result.final_state == "completed"


@pytest.mark.integration
@respx.mock
async def test_e2e_partial_failure() -> None:
    """One collector fails (network error), run state = partial.

    ct-crtsh is mocked to return a connection error while rdap-whois
    returns successfully. The run should complete in "partial" state
    because some dispatches succeeded and some failed.
    """
    # rdap-whois: succeeds normally.
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

    # ct-crtsh: health check passes, but the actual data fetch fails.
    respx.head("https://crt.sh/").mock(
        return_value=httpx.Response(200),
    )
    respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
        side_effect=httpx.ConnectError("connection refused"),
    )

    registry = _build_registry()
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

    # ct-crtsh raises CollectorSourceUnreachableError -> collector_error.
    # rdap-whois succeeds. Mixed result -> "partial".
    assert result.final_state == "partial"
    assert result.successful_dispatches > 0
    assert result.failed_dispatches > 0

    # rdap-whois observations should still have been upserted.
    assert entity_repo.create_or_update.call_count >= 1

    # State machine still transitions correctly.
    state_calls = run_repo.update_state.call_args_list
    assert len(state_calls) == 2
    assert state_calls[0].kwargs["new_state"] == "running"
    assert state_calls[1].kwargs["new_state"] == "partial"
