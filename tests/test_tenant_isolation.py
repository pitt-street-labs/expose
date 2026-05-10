"""Cross-tenant isolation test scaffold (per ADR-007 §When to revisit; issue #28).

The full isolation suite per ADR-007 needs to verify, for every API surface and data
path, that tenant A cannot reach tenant B's data. The full suite lands as the data
layer and API surface mature in Sprint 3-7. This file establishes the *scaffold* —
the markers, the synthetic-tenant fixtures, the expected test shapes — so that
isolation regressions are caught from the moment each surface lands.

CI MUST run any test marked `isolation` regardless of PR scope; failures block merge.
"""
from __future__ import annotations

from uuid import UUID

import pytest

from expose.types import TenantId

pytestmark = pytest.mark.isolation


# Synthetic tenants used across isolation tests. Real tenants get their UUIDs
# from the lifecycle API (Sprint 3+); these are stable test fixtures.
TENANT_A = TenantId(UUID("018f1f00-0000-7000-8000-00000000A001"))
TENANT_B = TenantId(UUID("018f1f00-0000-7000-8000-00000000B002"))


@pytest.fixture
def tenant_a() -> TenantId:
    return TENANT_A


@pytest.fixture
def tenant_b() -> TenantId:
    return TENANT_B


def test_synthetic_tenant_ids_are_distinct(tenant_a: TenantId, tenant_b: TenantId) -> None:
    """Sanity: the test fixtures themselves don't accidentally collide."""
    assert tenant_a != tenant_b


@pytest.mark.skip(reason="API surface lands in Sprint 3+; placeholder")
def test_tenant_a_cannot_read_tenant_b_artifacts_via_admin_api(
    tenant_a: TenantId,
    tenant_b: TenantId,
) -> None:
    """Admin API endpoints scoped to tenant A must reject tenant B artifact reads."""


@pytest.mark.skip(reason="Database layer lands in Sprint 1-2 → Sprint 3; placeholder")
def test_database_query_always_scopes_by_tenant_id(
    tenant_a: TenantId,
    tenant_b: TenantId,
) -> None:
    """Every relevant SELECT / UPDATE / DELETE must include `tenant_id` in WHERE."""


@pytest.mark.skip(reason="Caching layer lands in Sprint 5+; placeholder")
def test_caching_layer_keys_include_tenant_id(
    tenant_a: TenantId,
    tenant_b: TenantId,
) -> None:
    """Cache keys must include tenant_id so tenant A's cached data cannot leak to B."""


@pytest.mark.skip(reason="Job queue lands in Sprint 3+; placeholder")
def test_background_jobs_preserve_tenant_context_across_async_boundaries(
    tenant_a: TenantId,
) -> None:
    """A job dispatched with tenant A context must still have tenant A context when
    it runs on a worker (no leakage via global state, contextvars must propagate)."""


@pytest.mark.skip(reason="Bearer-token auth lands in Phase 3 production-hardening; placeholder")
def test_bearer_tokens_are_tenant_scoped(
    tenant_a: TenantId,
    tenant_b: TenantId,
) -> None:
    """A bearer token issued for tenant A cannot read tenant B endpoints."""


@pytest.mark.skip(reason="Audit log lands in Sprint 7+; placeholder")
def test_audit_log_entries_for_tenant_a_not_visible_to_tenant_b_admin(
    tenant_a: TenantId,
    tenant_b: TenantId,
) -> None:
    """Tenant A's audit log entries must not appear in queries scoped to tenant B."""


@pytest.mark.skip(reason="Run scheduling lands in Sprint 7+; placeholder")
def test_tenant_a_run_cannot_reference_tenant_b_seeds_rules_or_graph(
    tenant_a: TenantId,
    tenant_b: TenantId,
) -> None:
    """A run scoped to tenant A must reject any reference to tenant B's data
    (seeds, rule packs, observation graph entries, evidence)."""
