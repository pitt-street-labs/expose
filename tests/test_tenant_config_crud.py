"""Tests for the tenant configuration CRUD API.

Uses a minimal FastAPI app with the ``tenant_config`` router.  No database
is needed -- the config store is an in-memory dict, so each test module
gets a clean slate (the module-level ``_configs`` dict is cleared in the
fixture).

Covers:
 1. GET returns sensible defaults when no config has been set
 2. PUT replaces entire config
 3. PATCH updates only specified fields
 4. PATCH preserves unspecified fields
 5. Invalid egress_profile rejected (422)
 6. Invalid scope_rule type rejected (422)
 7. Multiple tenants have independent configs
 8. PUT resets unspecified fields to defaults
 9. GET after PUT returns the PUT'd config
10. PATCH with scope_rules containing is_exclusion flag
11. Extra fields rejected by extra="forbid" (422)
12. PATCH schedule_cron and llm settings
13. Multiple PATCHes accumulate correctly
14. Config independence after interleaved PUT/PATCH on different tenants
"""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from expose.api import tenant_config


def _make_app() -> Any:
    """Construct a minimal FastAPI app with the tenant config router."""
    from fastapi import FastAPI  # noqa: PLC0415

    app = FastAPI()
    app.include_router(tenant_config.router)
    return app


@pytest.fixture(autouse=True)
def _clear_config_store() -> None:
    """Reset the in-memory config store before each test."""
    tenant_config._configs.clear()


@pytest.fixture
def tenant_id() -> UUID:
    """A fixed tenant UUID for deterministic test URLs."""
    return uuid4()


@pytest.fixture
async def client() -> AsyncClient:
    """HTTPX async client wired to the minimal FastAPI app."""
    app = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac  # type: ignore[misc]


# === 1. GET returns defaults when no config has been set ====================


async def test_get_default_config(client: AsyncClient, tenant_id: UUID) -> None:
    resp = await client.get(f"/v1/tenants/{tenant_id}/config/")
    assert resp.status_code == 200
    data = resp.json()
    assert data["tenant_id"] == str(tenant_id)
    assert data["scope_rules"] == []
    assert data["enabled_collectors"] == []
    assert data["schedule_cron"] is None
    assert data["egress_profile"] == "direct"
    assert data["llm_enabled"] is False
    assert data["llm_provider"] is None
    assert data["llm_cost_ceiling_per_run"] == 0.0
    assert data["updated_by"] is None
    assert "updated_at" in data


# === 2. PUT replaces entire config ==========================================


async def test_put_replaces_config(client: AsyncClient, tenant_id: UUID) -> None:
    payload = {
        "scope_rules": [
            {"rule_type": "apex_domain", "value": "example.com"},
        ],
        "enabled_collectors": ["ct_crtsh", "rdap_whois"],
        "schedule_cron": "0 2 * * *",
        "egress_profile": "socks5",
        "llm_enabled": True,
        "llm_provider": "openai",
        "llm_cost_ceiling_per_run": 5.0,
    }
    resp = await client.put(f"/v1/tenants/{tenant_id}/config/", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["tenant_id"] == str(tenant_id)
    assert len(data["scope_rules"]) == 1
    assert data["scope_rules"][0]["rule_type"] == "apex_domain"
    assert data["scope_rules"][0]["value"] == "example.com"
    assert data["enabled_collectors"] == ["ct_crtsh", "rdap_whois"]
    assert data["schedule_cron"] == "0 2 * * *"
    assert data["egress_profile"] == "socks5"
    assert data["llm_enabled"] is True
    assert data["llm_provider"] == "openai"
    assert data["llm_cost_ceiling_per_run"] == 5.0
    assert data["updated_by"] == "api"


# === 3. PATCH updates only specified fields =================================


async def test_patch_updates_specified_fields(
    client: AsyncClient, tenant_id: UUID
) -> None:
    # First set a baseline via PUT
    await client.put(
        f"/v1/tenants/{tenant_id}/config/",
        json={
            "egress_profile": "socks5",
            "llm_enabled": True,
            "llm_provider": "openai",
            "llm_cost_ceiling_per_run": 5.0,
        },
    )
    # Now patch only egress_profile
    resp = await client.patch(
        f"/v1/tenants/{tenant_id}/config/",
        json={"egress_profile": "wireguard"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["egress_profile"] == "wireguard"


# === 4. PATCH preserves unspecified fields ==================================


async def test_patch_preserves_unspecified_fields(
    client: AsyncClient, tenant_id: UUID
) -> None:
    await client.put(
        f"/v1/tenants/{tenant_id}/config/",
        json={
            "egress_profile": "socks5",
            "llm_enabled": True,
            "llm_provider": "openai",
            "llm_cost_ceiling_per_run": 5.0,
            "enabled_collectors": ["ct_crtsh"],
        },
    )
    # Patch only llm_enabled
    resp = await client.patch(
        f"/v1/tenants/{tenant_id}/config/",
        json={"llm_enabled": False},
    )
    assert resp.status_code == 200
    data = resp.json()
    # Patched field changed
    assert data["llm_enabled"] is False
    # Unpatched fields preserved
    assert data["egress_profile"] == "socks5"
    assert data["llm_provider"] == "openai"
    assert data["llm_cost_ceiling_per_run"] == 5.0
    assert data["enabled_collectors"] == ["ct_crtsh"]


# === 5. Invalid egress_profile rejected (422) ===============================


async def test_invalid_egress_profile_rejected(
    client: AsyncClient, tenant_id: UUID
) -> None:
    resp = await client.put(
        f"/v1/tenants/{tenant_id}/config/",
        json={"egress_profile": "carrier_pigeon"},
    )
    assert resp.status_code == 422


async def test_invalid_egress_profile_rejected_patch(
    client: AsyncClient, tenant_id: UUID
) -> None:
    resp = await client.patch(
        f"/v1/tenants/{tenant_id}/config/",
        json={"egress_profile": "smoke_signal"},
    )
    assert resp.status_code == 422


# === 6. Invalid scope_rule type rejected (422) ==============================


async def test_invalid_scope_rule_type_rejected(
    client: AsyncClient, tenant_id: UUID
) -> None:
    resp = await client.put(
        f"/v1/tenants/{tenant_id}/config/",
        json={
            "scope_rules": [
                {"rule_type": "magic_beans", "value": "nope"},
            ],
        },
    )
    assert resp.status_code == 422


async def test_invalid_scope_rule_type_rejected_patch(
    client: AsyncClient, tenant_id: UUID
) -> None:
    resp = await client.patch(
        f"/v1/tenants/{tenant_id}/config/",
        json={
            "scope_rules": [
                {"rule_type": "not_a_real_type", "value": "bad"},
            ],
        },
    )
    assert resp.status_code == 422


# === 7. Multiple tenants have independent configs ===========================


async def test_independent_tenant_configs(client: AsyncClient) -> None:
    tid_a = uuid4()
    tid_b = uuid4()

    await client.put(
        f"/v1/tenants/{tid_a}/config/",
        json={"egress_profile": "socks5", "llm_enabled": True},
    )
    await client.put(
        f"/v1/tenants/{tid_b}/config/",
        json={"egress_profile": "wireguard", "llm_enabled": False},
    )

    resp_a = await client.get(f"/v1/tenants/{tid_a}/config/")
    resp_b = await client.get(f"/v1/tenants/{tid_b}/config/")

    assert resp_a.json()["egress_profile"] == "socks5"
    assert resp_a.json()["llm_enabled"] is True
    assert resp_b.json()["egress_profile"] == "wireguard"
    assert resp_b.json()["llm_enabled"] is False


# === 8. PUT resets unspecified fields to defaults ===========================


async def test_put_resets_unspecified_to_defaults(
    client: AsyncClient, tenant_id: UUID
) -> None:
    # Set everything
    await client.put(
        f"/v1/tenants/{tenant_id}/config/",
        json={
            "egress_profile": "socks5",
            "llm_enabled": True,
            "llm_provider": "openai",
            "llm_cost_ceiling_per_run": 10.0,
            "enabled_collectors": ["ct_crtsh", "rdap_whois"],
            "schedule_cron": "0 * * * *",
        },
    )
    # PUT with only egress_profile -- everything else should reset
    resp = await client.put(
        f"/v1/tenants/{tenant_id}/config/",
        json={"egress_profile": "direct"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["egress_profile"] == "direct"
    # These should have been reset to defaults
    assert data["llm_enabled"] is False
    assert data["llm_provider"] is None
    assert data["llm_cost_ceiling_per_run"] == 0.0
    assert data["enabled_collectors"] == []
    assert data["schedule_cron"] is None


# === 9. GET after PUT returns the PUT'd config ==============================


async def test_get_after_put(client: AsyncClient, tenant_id: UUID) -> None:
    payload = {
        "scope_rules": [
            {"rule_type": "cidr", "value": "10.0.0.0/8"},
            {"rule_type": "asn", "value": "AS12345"},
        ],
        "enabled_collectors": ["passive_dns"],
        "egress_profile": "http_connect",
        "llm_enabled": True,
        "llm_provider": "anthropic",
        "llm_cost_ceiling_per_run": 2.5,
    }
    await client.put(f"/v1/tenants/{tenant_id}/config/", json=payload)

    resp = await client.get(f"/v1/tenants/{tenant_id}/config/")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["scope_rules"]) == 2
    assert data["scope_rules"][0]["rule_type"] == "cidr"
    assert data["scope_rules"][1]["rule_type"] == "asn"
    assert data["enabled_collectors"] == ["passive_dns"]
    assert data["egress_profile"] == "http_connect"
    assert data["llm_enabled"] is True
    assert data["llm_provider"] == "anthropic"
    assert data["llm_cost_ceiling_per_run"] == 2.5


# === 10. PATCH with scope_rules containing is_exclusion flag ================


async def test_scope_rules_with_exclusion(
    client: AsyncClient, tenant_id: UUID
) -> None:
    resp = await client.patch(
        f"/v1/tenants/{tenant_id}/config/",
        json={
            "scope_rules": [
                {"rule_type": "apex_domain", "value": "example.com"},
                {
                    "rule_type": "exact_domain",
                    "value": "internal.example.com",
                    "is_exclusion": True,
                },
            ],
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["scope_rules"]) == 2
    assert data["scope_rules"][0]["is_exclusion"] is False
    assert data["scope_rules"][1]["is_exclusion"] is True
    assert data["scope_rules"][1]["value"] == "internal.example.com"


# === 11. Extra fields rejected by extra="forbid" (422) ======================


async def test_extra_fields_rejected(
    client: AsyncClient, tenant_id: UUID
) -> None:
    resp = await client.put(
        f"/v1/tenants/{tenant_id}/config/",
        json={"egress_profile": "direct", "evil_field": "hacked"},
    )
    assert resp.status_code == 422


# === 12. PATCH schedule_cron and llm settings ===============================


async def test_patch_schedule_and_llm(
    client: AsyncClient, tenant_id: UUID
) -> None:
    resp = await client.patch(
        f"/v1/tenants/{tenant_id}/config/",
        json={
            "schedule_cron": "30 4 * * 1",
            "llm_enabled": True,
            "llm_provider": "anthropic",
            "llm_cost_ceiling_per_run": 1.25,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["schedule_cron"] == "30 4 * * 1"
    assert data["llm_enabled"] is True
    assert data["llm_provider"] == "anthropic"
    assert data["llm_cost_ceiling_per_run"] == 1.25


# === 13. Multiple PATCHes accumulate correctly ==============================


async def test_multiple_patches_accumulate(
    client: AsyncClient, tenant_id: UUID
) -> None:
    # First patch
    await client.patch(
        f"/v1/tenants/{tenant_id}/config/",
        json={"egress_profile": "socks5"},
    )
    # Second patch
    await client.patch(
        f"/v1/tenants/{tenant_id}/config/",
        json={"llm_enabled": True},
    )
    # Third patch
    await client.patch(
        f"/v1/tenants/{tenant_id}/config/",
        json={"enabled_collectors": ["ct_crtsh"]},
    )

    resp = await client.get(f"/v1/tenants/{tenant_id}/config/")
    data = resp.json()
    assert data["egress_profile"] == "socks5"
    assert data["llm_enabled"] is True
    assert data["enabled_collectors"] == ["ct_crtsh"]


# === 14. Config independence after interleaved operations ===================


async def test_interleaved_operations_independent(
    client: AsyncClient,
) -> None:
    tid_a = uuid4()
    tid_b = uuid4()

    # Interleave PUT/PATCH across two tenants
    await client.put(
        f"/v1/tenants/{tid_a}/config/",
        json={"egress_profile": "direct", "llm_enabled": False},
    )
    await client.patch(
        f"/v1/tenants/{tid_b}/config/",
        json={"egress_profile": "wireguard"},
    )
    await client.patch(
        f"/v1/tenants/{tid_a}/config/",
        json={"llm_enabled": True},
    )
    await client.put(
        f"/v1/tenants/{tid_b}/config/",
        json={"llm_enabled": False, "enabled_collectors": ["shodan"]},
    )

    resp_a = await client.get(f"/v1/tenants/{tid_a}/config/")
    resp_b = await client.get(f"/v1/tenants/{tid_b}/config/")

    data_a = resp_a.json()
    data_b = resp_b.json()

    assert data_a["egress_profile"] == "direct"
    assert data_a["llm_enabled"] is True
    assert data_b["egress_profile"] == "direct"  # PUT reset from wireguard
    assert data_b["llm_enabled"] is False
    assert data_b["enabled_collectors"] == ["shodan"]
    assert data_a["enabled_collectors"] == []  # Not affected by B's PUT
