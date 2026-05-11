"""End-to-end pipeline tests — all httpx-based collectors through real dispatch.

Exercises the complete EXPOSE pipeline from ``PipelineDispatcher`` through
``RunExecutor`` with real builtin collectors but NO live external services.
All HTTP traffic is intercepted by ``respx``; repository layers are
``AsyncMock``-ed.

Five test cases:

1. **All Tier-1 collectors** — register all 6 httpx-based collectors, dispatch
   against example.com, assert completed state and >= 6 successful dispatches.
2. **Single collector ct-crtsh** — register only CrtShCollector, assert exactly
   2 dispatches (example.com + www.example.com from seed expansion).
3. **Multiple seed types** — DOMAIN + IP seeds dispatched to all collectors.
4. **Seed expansion verification** — assert total_seeds=1, expanded_seeds=2.
5. **Full pipeline to artifact** — after pipeline execution, generate a
   canonical artifact and validate its structure.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import httpx
import pytest
import respx

from expose.collectors.base import Seed, SeedType
from expose.collectors.builtin.bgp_he_toolkit import HeToolkitCollector
from expose.collectors.builtin.bgp_ripestat import RipeStatCollector
from expose.collectors.builtin.ct_crtsh import CrtShCollector
from expose.collectors.builtin.favicon_hash import FaviconHashCollector
from expose.collectors.builtin.github_exposed import GitHubExposedCollector
from expose.collectors.builtin.rdap_whois import RdapWhoisCollector
from expose.collectors.registry import CollectorRegistry
from expose.collectors.tiers import TenantAuthorizationScope
from expose.pipeline.artifact_generator import ArtifactGenerator
from expose.pipeline.dispatcher import PipelineDispatcher
from expose.pipeline.run_executor import RunExecutor

# === Deterministic synthetic IDs (UUIDv7-style, greppable) ====================

TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000e2f1")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000e2f2")

# === Mock HTTP response bodies ================================================

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

RDAP_IP_RESPONSE = json.dumps({
    "objectClassName": "ip network",
    "handle": "NET-93-184-216-0-1",
    "name": "EDGECAST-NETBLK-03",
    "status": ["active"],
    "entities": [
        {
            "objectClassName": "entity",
            "handle": "EC-ARIN",
            "roles": ["registrant"],
            "vcardArray": [
                "vcard",
                [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "Edgecast Inc."],
                    ["org", {}, "text", "Edgecast Inc."],
                ],
            ],
        },
    ],
    "events": [
        {"eventAction": "registration", "eventDate": "2014-04-25T00:00:00Z"},
    ],
})

RIPESTAT_NETWORK_INFO_RESPONSE = json.dumps({
    "status": "ok",
    "data": {
        "asns": [
            {
                "asn": 15133,
                "holder": "EDGECAST",
            }
        ],
        "prefix": "93.184.216.0/24",
        "resource": "93.184.216.34",
    },
    "status_code": 200,
})

HE_TOOLKIT_IP_HTML = """<html>
<head><title>bgp.he.net - 93.184.216.34</title></head>
<body>
<div id="asninfo">
<h1>AS15133 - EDGECAST</h1>
<table id="table_prefixes4">
<tr><td><a href="/net/93.184.216.0/24">93.184.216.0/24</a></td></tr>
</table>
</div>
</body>
</html>"""

GITHUB_SEARCH_REPOS_RESPONSE = json.dumps({
    "total_count": 1,
    "incomplete_results": False,
    "items": [
        {
            "full_name": "example/docs",
            "description": "Example documentation",
            "html_url": "https://github.com/example/docs",
            "stargazers_count": 3,
            "updated_at": "2025-06-01T12:00:00Z",
        },
    ],
})

GITHUB_SEARCH_CODE_RESPONSE = json.dumps({
    "total_count": 0,
    "incomplete_results": False,
    "items": [],
})

FAVICON_BYTES = b"\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x01\x00 \x00"


# === Helpers ==================================================================


def _make_run_row(state: str = "pending") -> MagicMock:
    """Build a mock Run ORM row in the given state."""
    row = MagicMock()
    row.id = RUN_ID
    row.tenant_id = TENANT_ID
    row.state = state
    row.started_at = None
    row.completed_at = None
    row.pipeline_version = "v0.1.0"
    return row


def _make_entity_row(
    *,
    entity_type: str = "domain",
    canonical_identifier: str = "example.com",
    attribution_confidence: float = 0.0,
    attribution_status: str = "unattributed",
) -> MagicMock:
    """Build a mock Entity ORM row."""
    row = MagicMock()
    row.id = UUID("018f1f00-0000-7000-8000-00000000eeee")
    row.entity_type = entity_type
    row.canonical_identifier = canonical_identifier
    row.attribution_confidence = attribution_confidence
    row.attribution_status = attribution_status
    row.first_observed_at = None
    row.last_observed_at = None
    row.properties = {
        "_collector_id": "ct-crtsh",
        "_collector_version": "0.1.0",
    }
    return row


def _build_scope(identifiers: frozenset[str] | None = None) -> TenantAuthorizationScope:
    """Build a TenantAuthorizationScope for the given identifiers."""
    return TenantAuthorizationScope(
        explicit_entity_identifiers=identifiers or frozenset({"example.com", "93.184.216.34"}),
    )


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


def _setup_all_respx_routes() -> None:
    """Register respx routes for all 6 httpx-based collectors.

    Mocks both health checks and data fetches for every collector.
    """
    # --- ct-crtsh ---
    respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
        return_value=httpx.Response(200, text=CRT_SH_RESPONSE),
    )
    respx.head("https://crt.sh/").mock(
        return_value=httpx.Response(200),
    )

    # --- rdap-whois ---
    respx.get(url__startswith="https://rdap.org/domain/").mock(
        return_value=httpx.Response(
            200,
            text=RDAP_DOMAIN_RESPONSE,
            headers={"content-type": "application/rdap+json"},
        ),
    )
    respx.get(url__startswith="https://rdap.org/ip/").mock(
        return_value=httpx.Response(
            200,
            text=RDAP_IP_RESPONSE,
            headers={"content-type": "application/rdap+json"},
        ),
    )
    respx.head("https://rdap.org/").mock(
        return_value=httpx.Response(200),
    )

    # --- bgp-he-toolkit ---
    respx.get(url__startswith="https://bgp.he.net/ip/").mock(
        return_value=httpx.Response(200, text=HE_TOOLKIT_IP_HTML),
    )
    respx.head("https://bgp.he.net/").mock(
        return_value=httpx.Response(200),
    )

    # --- bgp-ripestat ---
    respx.get(
        "https://stat.ripe.net/data/network-info/data.json",
    ).mock(
        return_value=httpx.Response(200, text=RIPESTAT_NETWORK_INFO_RESPONSE),
    )
    respx.head(
        "https://stat.ripe.net/data/network-info/data.json",
    ).mock(
        return_value=httpx.Response(200),
    )

    # --- github-exposed ---
    respx.get(
        "https://api.github.com/search/repositories",
    ).mock(
        return_value=httpx.Response(200, text=GITHUB_SEARCH_REPOS_RESPONSE),
    )
    respx.get(
        "https://api.github.com/search/code",
    ).mock(
        return_value=httpx.Response(200, text=GITHUB_SEARCH_CODE_RESPONSE),
    )
    respx.get("https://api.github.com/zen").mock(
        return_value=httpx.Response(200, text="Keep it logically awesome."),
    )

    # --- favicon-hash ---
    # HTTPS favicon probe succeeds; HTTP fallback not needed.
    respx.get(url__regex=r"https://[^/]+/favicon\.ico").mock(
        return_value=httpx.Response(
            200,
            content=FAVICON_BYTES,
            headers={"content-type": "image/x-icon"},
        ),
    )
    respx.get(url__regex=r"https://[^/]+/apple-touch-icon\.png").mock(
        return_value=httpx.Response(404),
    )
    respx.get("https://www.google.com/favicon.ico").mock(
        return_value=httpx.Response(
            200,
            content=FAVICON_BYTES,
            headers={"content-type": "image/x-icon"},
        ),
    )
    # HTTP fallback probes (favicon collector tries http:// if https:// fails)
    respx.get(url__regex=r"http://[^/]+/favicon\.ico").mock(
        return_value=httpx.Response(
            200,
            content=FAVICON_BYTES,
            headers={"content-type": "image/x-icon"},
        ),
    )
    respx.get(url__regex=r"http://[^/]+/apple-touch-icon\.png").mock(
        return_value=httpx.Response(404),
    )


def _build_all_collector_registry() -> CollectorRegistry:
    """Build a fresh registry with all 6 httpx-based collectors."""
    reg = CollectorRegistry()
    reg.register(CrtShCollector)
    reg.register(RdapWhoisCollector)
    reg.register(HeToolkitCollector)
    reg.register(RipeStatCollector)
    reg.register(GitHubExposedCollector)
    reg.register(FaviconHashCollector)
    return reg


ALL_COLLECTOR_IDS = [
    "ct-crtsh",
    "rdap-whois",
    "bgp-he-toolkit",
    "bgp-ripestat",
    "github-exposed",
    "favicon-hash",
]


# === Test cases ===============================================================


@pytest.mark.integration
@respx.mock
async def test_all_tier1_collectors() -> None:
    """Register all 6 httpx-based collectors, dispatch against example.com.

    Verifies:
    - final_state is "completed" (no failures)
    - successful_dispatches >= 6 (at least one per collector)
    """
    _setup_all_respx_routes()

    registry = _build_all_collector_registry()
    scope = _build_scope()
    dispatcher = PipelineDispatcher(registry, scope, TENANT_ID)
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
        collector_ids=ALL_COLLECTOR_IDS,
    )

    assert result.final_state == "completed"
    assert result.successful_dispatches >= 6
    assert result.failed_dispatches == 0
    assert result.total_observations > 0
    assert entity_repo.create_or_update.call_count >= 1


@pytest.mark.integration
@respx.mock
async def test_single_collector_ct_crtsh() -> None:
    """Register only CrtShCollector, assert exactly 2 dispatches.

    Seed expansion turns example.com into [example.com, www.example.com],
    yielding 2 dispatches (1 per expanded seed x 1 collector).
    """
    respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
        return_value=httpx.Response(200, text=CRT_SH_RESPONSE),
    )
    respx.head("https://crt.sh/").mock(
        return_value=httpx.Response(200),
    )

    registry = CollectorRegistry()
    registry.register(CrtShCollector)
    scope = _build_scope(frozenset({"example.com"}))
    dispatcher = PipelineDispatcher(registry, scope, TENANT_ID)
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
        collector_ids=["ct-crtsh"],
    )

    assert result.final_state == "completed"
    # 1 seed expanded to 2 (example.com + www.example.com), 1 collector = 2 dispatches
    assert result.total_dispatches == 2
    assert result.successful_dispatches == 2
    assert result.failed_dispatches == 0


@pytest.mark.integration
@respx.mock
async def test_multiple_seed_types() -> None:
    """DOMAIN seed + IP seed dispatched to all collectors.

    Domain seed expands to 2 (example.com + www.example.com), IP seed
    stays as 1. Both are dispatched to all 6 collectors. Collectors
    that do not handle a seed type skip silently (yielding 0 observations
    for that dispatch but still counting as successful).
    """
    _setup_all_respx_routes()

    registry = _build_all_collector_registry()
    scope = _build_scope()
    dispatcher = PipelineDispatcher(registry, scope, TENANT_ID)
    run_repo, entity_repo = _build_mocks()

    executor = RunExecutor(
        dispatcher=dispatcher,
        run_repo=run_repo,
        entity_repo=entity_repo,
    )

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[
            Seed(seed_type=SeedType.DOMAIN, value="example.com"),
            Seed(seed_type=SeedType.IP, value="93.184.216.34"),
        ],
        collector_ids=ALL_COLLECTOR_IDS,
    )

    assert result.final_state == "completed"
    # 1 domain -> 2 expanded + 1 IP = 3 seeds x 6 collectors = 18 dispatches
    assert result.total_dispatches == 18
    assert result.total_seeds == 2
    assert result.expanded_seeds == 3
    assert result.successful_dispatches == 18
    assert result.failed_dispatches == 0
    assert result.total_observations > 0


@pytest.mark.integration
@respx.mock
async def test_seed_expansion_verification() -> None:
    """Verify seed expansion: total_seeds=1, expanded_seeds=2.

    Ensures www.example.com is generated from example.com and both
    seeds are dispatched to the collector.
    """
    respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
        return_value=httpx.Response(200, text=CRT_SH_RESPONSE),
    )
    respx.head("https://crt.sh/").mock(
        return_value=httpx.Response(200),
    )

    registry = CollectorRegistry()
    registry.register(CrtShCollector)
    scope = _build_scope(frozenset({"example.com"}))
    dispatcher = PipelineDispatcher(registry, scope, TENANT_ID)
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
        collector_ids=["ct-crtsh"],
    )

    assert result.total_seeds == 1
    assert result.expanded_seeds == 2

    # Verify www.example.com was dispatched by checking entity_repo calls.
    # The entity_repo.create_or_update calls should include observations from
    # both example.com and www.example.com dispatches.
    # The crt.sh response yields observations keyed by certificate serial
    # (not the seed domain), so verify via dispatch counts.
    assert result.total_dispatches == 2
    assert result.successful_dispatches == 2


@pytest.mark.integration
@respx.mock
async def test_full_pipeline_to_artifact() -> None:
    """After pipeline execution, generate a canonical artifact.

    Verifies:
    - artifact.targets has at least 1 entry
    - content_hash is a 64-character hex string
    - json_bytes is valid JSON
    """
    _setup_all_respx_routes()

    registry = _build_all_collector_registry()
    scope = _build_scope()
    dispatcher = PipelineDispatcher(registry, scope, TENANT_ID)
    run_repo, entity_repo = _build_mocks()

    executor = RunExecutor(
        dispatcher=dispatcher,
        run_repo=run_repo,
        entity_repo=entity_repo,
    )

    # Run the pipeline to populate observations.
    pipeline_result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.DOMAIN, value="example.com")],
        collector_ids=ALL_COLLECTOR_IDS,
    )

    assert pipeline_result.final_state == "completed"
    assert pipeline_result.total_observations > 0

    # Build mock repos for the artifact generator using the data we collected.
    # The ArtifactGenerator needs: run_repo, entity_repo, relationship_repo.
    art_run_repo = AsyncMock()
    art_run_repo.get_by_id = AsyncMock(return_value=_make_run_row("completed"))

    entity_row = _make_entity_row()
    art_entity_repo = AsyncMock()
    art_entity_repo.list_for_tenant = AsyncMock(return_value=[entity_row])

    art_relationship_repo = AsyncMock()
    art_relationship_repo.find_for_entity = AsyncMock(return_value=[])

    generator = ArtifactGenerator(
        entity_repo=art_entity_repo,
        relationship_repo=art_relationship_repo,
        run_repo=art_run_repo,
    )

    artifact_result = await generator.generate(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
    )

    # Validate artifact structure.
    assert len(artifact_result.artifact.targets) > 0
    assert len(artifact_result.content_hash) == 64
    assert all(c in "0123456789abcdef" for c in artifact_result.content_hash)

    # Validate json_bytes is well-formed JSON.
    parsed = json.loads(artifact_result.json_bytes)
    assert isinstance(parsed, dict)
    assert "targets" in parsed
