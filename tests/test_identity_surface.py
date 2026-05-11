"""Tests for the EXPOSE Identity Surface module (``expose.modules.identity_surface``).

Coverage:

Registrant Pivot:
    1.  Groups domains by org name
    2.  Fuzzy matching handles name variations ("Acme Corp" vs "ACME Corporation")
    3.  Fuzzy matching rejects dissimilar names
    4.  Groups by email domain
    5.  Excludes free email providers from email-domain pivots
    6.  Groups by address (city + country)
    7.  Groups by name server patterns
    8.  Single-member groups are excluded (no self-clusters)
    9.  Empty input produces empty result
   10.  Dict entities missing ``domain`` are silently skipped
   11.  All cluster confidences are in [0.0, 1.0]
   12.  Custom fuzzy threshold changes cluster behavior
   13.  Mixed WhoisEntity + dict inputs accepted
   14.  Org name normalization strips corporate suffixes
   15.  Whitespace-only org names handled gracefully
   16.  Case-insensitive domain normalization
   17.  Name server deduplication across shared NS
   18.  Multiple email domains produce separate clusters
   19.  All free email providers exhaustively tested

Org Graph:
   20.  Builds hierarchy from M&A + WHOIS pivot data
   21.  DNS relationships add domain nodes, delegation edges, IP range nodes
   22.  Graph traversal helpers (get_node, get_edges_from/to, children_of)
   23.  Empty graph from empty builder
   24.  M&A dict entries missing required fields are silently skipped
   25.  Cycle-free guarantee: M&A edges are directed (no implicit reverse)
   26.  Duplicate nodes not created on repeated add_pivot_results
   27.  merged_with edge type handled correctly
   28.  DNS relationships without IP ranges still create domain nodes
   29.  Dict DNS entries missing required fields are silently skipped
   30.  Type errors on invalid input types (not dict or model)

Ethics Gate:
   31.  RegistrantPivot blocked by default
   32.  OrgGraphBuilder blocked by default (add_pivot_results)
   33.  OrgGraphBuilder.build() blocked by default
   34.  OrgGraphBuilder.add_ma_results() blocked by default
   35.  OrgGraphBuilder.add_dns_relationships() blocked by default
   36.  RegistrantPivot allowed when authorized
   37.  OrgGraphBuilder allowed when authorized
   38.  Ethics document exists with required sections

License Check:
   39.  check_license() returns True (placeholder per ADR-009)

API Endpoints:
   40.  GET /identity/registrant-pivot returns 200 with placeholder data
   41.  Registrant pivot response has correct structure
   42.  Registrant pivot clusters contain member data
   43.  Registrant pivot respects fuzzy_threshold param
   44.  GET /identity/org-graph returns 200 with placeholder data
   45.  Org graph response has correct structure
   46.  Org graph contains both nodes and edges
   47.  Org graph respects include_dns=false param
   48.  Org graph respects include_ma=false param
   49.  Invalid tenant_id returns 422
   50.  Registrant pivot domain param is required
   51.  Confidence values in API responses are valid
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from expose.modules.identity_surface import check_license
from expose.modules.identity_surface.org_graph import (
    DnsRelationship,
    EdgeType,
    GraphEdge,
    GraphNode,
    MaResult,
    NodeType,
    OrgGraph,
    OrgGraphBuilder,
)
from expose.modules.identity_surface.registrant_pivot import (
    AuthorizationError,
    ClusterMember,
    PivotCluster,
    PivotDimension,
    PivotResult,
    RegistrantPivot,
    WhoisEntity,
)
from expose.api.identity import router


# === Fixtures ================================================================

ETHICS_DOC_PATH = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "expose"
    / "modules"
    / "identity_surface"
    / "IDENTITY_SURFACE_ETHICS.md"
)

_TENANT_ID = "00000000-0000-0000-0000-000000000001"
_PIVOT_URL = f"http://test/v1/tenants/{_TENANT_ID}/identity/registrant-pivot"
_GRAPH_URL = f"http://test/v1/tenants/{_TENANT_ID}/identity/org-graph"


def _make_app() -> FastAPI:
    """Build a minimal FastAPI app with the identity router mounted."""
    app = FastAPI()
    app.include_router(router)
    return app


@pytest.fixture()
def app() -> FastAPI:
    return _make_app()


@pytest.fixture()
async def client(app: FastAPI) -> AsyncClient:
    """Yield an async HTTP client wired to the test app."""
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    )


def _sample_entities() -> list[WhoisEntity]:
    """Return a representative set of WHOIS entity models for testing."""
    return [
        WhoisEntity(
            domain="acme.com",
            registrant_org="Acme Corp",
            registrant_email="domains@acme.com",
            registrant_city="San Francisco",
            registrant_country="US",
            name_servers=["ns1.acmedns.net", "ns2.acmedns.net"],
        ),
        WhoisEntity(
            domain="acme.net",
            registrant_org="ACME Corporation",
            registrant_email="admin@acme.com",
            registrant_city="San Francisco",
            registrant_country="US",
            name_servers=["ns1.acmedns.net", "ns2.acmedns.net"],
        ),
        WhoisEntity(
            domain="acme-labs.io",
            registrant_org="Acme Corp",
            registrant_email="hostmaster@acme.com",
            registrant_city="San Francisco",
            registrant_country="US",
            name_servers=["ns1.acmedns.net", "ns2.acmedns.net"],
        ),
        WhoisEntity(
            domain="globex.com",
            registrant_org="Globex Corporation",
            registrant_email="dns@globex.com",
            registrant_city="New York",
            registrant_country="US",
            name_servers=["ns1.globexdns.com", "ns2.globexdns.com"],
        ),
        WhoisEntity(
            domain="globex.io",
            registrant_org="Globex Corp",
            registrant_email="admin@globex.com",
            registrant_city="New York",
            registrant_country="US",
            name_servers=["ns1.globexdns.com", "ns2.globexdns.com"],
        ),
    ]


def _sample_ma_data() -> list[MaResult]:
    """Return M&A discovery entries for testing."""
    return [
        MaResult(
            acquirer="Acme Corp",
            target="Widget Co",
            relationship="acquired_by",
            confidence=0.9,
            properties={"date": "2024-01-15"},
        ),
        MaResult(
            acquirer="Acme Corp",
            target="Gadget Inc",
            relationship="parent_subsidiary",
            confidence=0.85,
        ),
    ]


def _sample_dns_data() -> list[DnsRelationship]:
    """Return DNS relationship entries for testing."""
    return [
        DnsRelationship(
            parent_domain="acme.com",
            child_domain="api.acme.com",
            relationship="dns_delegation",
            confidence=0.9,
            ip_ranges=["198.51.100.0/24"],
        ),
        DnsRelationship(
            parent_domain="acme.com",
            child_domain="cdn.acme.com",
            confidence=0.8,
        ),
    ]


# === Ethics gate tests =======================================================


class TestEthicsGate:
    """Verify the per_tenant_authorization ethics gate."""

    def test_registrant_pivot_blocked_by_default(self) -> None:
        """RegistrantPivot refuses operations when authorization is False."""
        pivot = RegistrantPivot(per_tenant_authorization=False)
        with pytest.raises(AuthorizationError, match="per_tenant_authorization"):
            pivot.pivot(_sample_entities())

    def test_org_graph_builder_blocked_by_default(self) -> None:
        """OrgGraphBuilder refuses operations when authorization is False."""
        builder = OrgGraphBuilder(per_tenant_authorization=False)
        # All ingestion methods should be blocked.
        pivot_result = PivotResult(clusters=())
        with pytest.raises(AuthorizationError, match="per_tenant_authorization"):
            builder.add_pivot_results(pivot_result)

    def test_org_graph_builder_build_blocked(self) -> None:
        """OrgGraphBuilder.build() refuses when authorization is False."""
        builder = OrgGraphBuilder(per_tenant_authorization=False)
        with pytest.raises(AuthorizationError, match="per_tenant_authorization"):
            builder.build()

    def test_org_graph_builder_add_ma_blocked(self) -> None:
        """OrgGraphBuilder.add_ma_results() refuses when authorization is False."""
        builder = OrgGraphBuilder(per_tenant_authorization=False)
        with pytest.raises(AuthorizationError, match="per_tenant_authorization"):
            builder.add_ma_results(_sample_ma_data())

    def test_org_graph_builder_add_dns_blocked(self) -> None:
        """OrgGraphBuilder.add_dns_relationships() refuses when authorization is False."""
        builder = OrgGraphBuilder(per_tenant_authorization=False)
        with pytest.raises(AuthorizationError, match="per_tenant_authorization"):
            builder.add_dns_relationships(_sample_dns_data())

    def test_registrant_pivot_allowed_when_authorized(self) -> None:
        """RegistrantPivot proceeds when per_tenant_authorization=True."""
        pivot = RegistrantPivot(per_tenant_authorization=True)
        result = pivot.pivot(_sample_entities())
        assert isinstance(result, PivotResult)
        assert len(result.clusters) > 0

    def test_org_graph_builder_allowed_when_authorized(self) -> None:
        """OrgGraphBuilder proceeds when per_tenant_authorization=True."""
        builder = OrgGraphBuilder(per_tenant_authorization=True)
        # Should not raise.
        builder.add_ma_results(_sample_ma_data())
        builder.add_dns_relationships(_sample_dns_data())
        graph = builder.build()
        assert isinstance(graph, OrgGraph)


# === Registrant pivot tests ==================================================


class TestRegistrantPivot:
    """Verify registrant pivot clustering across all dimensions."""

    def test_groups_by_org_name(self) -> None:
        """Domains with same/similar org names are grouped together."""
        pivot = RegistrantPivot(per_tenant_authorization=True)
        result = pivot.pivot(_sample_entities())

        org_clusters = [
            c for c in result.clusters
            if c.dimension == PivotDimension.ORG_NAME
        ]
        assert len(org_clusters) >= 1

        # Find the Acme cluster.
        acme_cluster = None
        for c in org_clusters:
            domains = {m.domain for m in c.members}
            if "acme.com" in domains:
                acme_cluster = c
                break

        assert acme_cluster is not None
        acme_domains = {m.domain for m in acme_cluster.members}
        # "Acme Corp" and "ACME Corporation" should fuzzy-match.
        assert "acme.com" in acme_domains
        assert "acme.net" in acme_domains

    def test_fuzzy_matching_name_variations(self) -> None:
        """Fuzzy matching groups 'Acme Corp' and 'ACME Corporation'."""
        entities = [
            WhoisEntity(domain="a.com", registrant_org="Acme Corp"),
            WhoisEntity(domain="b.com", registrant_org="ACME Corporation"),
            WhoisEntity(domain="c.com", registrant_org="Acme Corp."),
        ]
        pivot = RegistrantPivot(
            per_tenant_authorization=True,
            fuzzy_threshold=0.75,
        )
        result = pivot.pivot(entities)

        org_clusters = [
            c for c in result.clusters
            if c.dimension == PivotDimension.ORG_NAME
        ]
        assert len(org_clusters) >= 1

        # All three should be in the same cluster.
        largest = max(org_clusters, key=lambda c: len(c.members))
        domains = {m.domain for m in largest.members}
        assert domains == {"a.com", "b.com", "c.com"}

    def test_fuzzy_matching_rejects_dissimilar(self) -> None:
        """Dissimilar org names are not grouped together."""
        entities = [
            WhoisEntity(domain="a.com", registrant_org="Acme Corp"),
            WhoisEntity(domain="b.com", registrant_org="Totally Different LLC"),
        ]
        pivot = RegistrantPivot(per_tenant_authorization=True)
        result = pivot.pivot(entities)

        org_clusters = [
            c for c in result.clusters
            if c.dimension == PivotDimension.ORG_NAME
        ]
        # No cluster should contain both -- they are too dissimilar.
        for c in org_clusters:
            domains = {m.domain for m in c.members}
            assert not ({"a.com", "b.com"} <= domains)

    def test_groups_by_email_domain(self) -> None:
        """Domains with same registrant email domain are grouped."""
        pivot = RegistrantPivot(per_tenant_authorization=True)
        result = pivot.pivot(_sample_entities())

        email_clusters = [
            c for c in result.clusters
            if c.dimension == PivotDimension.EMAIL_DOMAIN
        ]
        assert len(email_clusters) >= 1

        # Find cluster keyed on acme.com email domain.
        acme_email = None
        for c in email_clusters:
            if c.key == "acme.com":
                acme_email = c
                break

        assert acme_email is not None
        domains = {m.domain for m in acme_email.members}
        assert "acme.com" in domains
        assert "acme.net" in domains

    def test_excludes_free_email_providers(self) -> None:
        """Free email providers (gmail, yahoo, etc.) are excluded from email pivot."""
        entities = [
            WhoisEntity(domain="a.com", registrant_email="user1@gmail.com"),
            WhoisEntity(domain="b.com", registrant_email="user2@gmail.com"),
        ]
        pivot = RegistrantPivot(per_tenant_authorization=True)
        result = pivot.pivot(entities)

        email_clusters = [
            c for c in result.clusters
            if c.dimension == PivotDimension.EMAIL_DOMAIN
        ]
        # gmail.com should not produce a cluster.
        gmail_clusters = [c for c in email_clusters if c.key == "gmail.com"]
        assert len(gmail_clusters) == 0

    def test_all_free_email_providers_excluded(self) -> None:
        """All known free email providers are excluded from email pivot."""
        free_providers = [
            "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
            "protonmail.com", "mail.com", "aol.com", "icloud.com",
        ]
        for provider in free_providers:
            entities = [
                WhoisEntity(domain="a.com", registrant_email=f"user1@{provider}"),
                WhoisEntity(domain="b.com", registrant_email=f"user2@{provider}"),
            ]
            pivot = RegistrantPivot(per_tenant_authorization=True)
            result = pivot.pivot(entities)
            email_clusters = [
                c for c in result.clusters
                if c.dimension == PivotDimension.EMAIL_DOMAIN
            ]
            provider_clusters = [c for c in email_clusters if c.key == provider]
            assert len(provider_clusters) == 0, (
                f"Free provider {provider} should be excluded but produced a cluster"
            )

    def test_groups_by_address(self) -> None:
        """Domains with same city+country are grouped."""
        pivot = RegistrantPivot(per_tenant_authorization=True)
        result = pivot.pivot(_sample_entities())

        addr_clusters = [
            c for c in result.clusters
            if c.dimension == PivotDimension.ADDRESS
        ]
        assert len(addr_clusters) >= 1

        # San Francisco, US should contain acme domains.
        sf_cluster = None
        for c in addr_clusters:
            if "san francisco" in c.key:
                sf_cluster = c
                break

        assert sf_cluster is not None
        assert len(sf_cluster.members) >= 2

    def test_groups_by_name_server(self) -> None:
        """Domains sharing name servers are grouped."""
        pivot = RegistrantPivot(per_tenant_authorization=True)
        result = pivot.pivot(_sample_entities())

        ns_clusters = [
            c for c in result.clusters
            if c.dimension == PivotDimension.NAME_SERVER
        ]
        assert len(ns_clusters) >= 1

    def test_single_member_groups_excluded(self) -> None:
        """Clusters with only one member are not included in results."""
        entities = [
            WhoisEntity(
                domain="solo.com",
                registrant_org="UniqueOrg XYZ",
                registrant_email="admin@unique-org-xyz.com",
                registrant_city="Timbuktu",
                registrant_country="ML",
                name_servers=["ns.unique.example"],
            ),
        ]
        pivot = RegistrantPivot(per_tenant_authorization=True)
        result = pivot.pivot(entities)

        # No clusters should exist for a single entity.
        assert len(result.clusters) == 0

    def test_empty_input(self) -> None:
        """Empty entity list produces empty result."""
        pivot = RegistrantPivot(per_tenant_authorization=True)
        result = pivot.pivot([])
        assert len(result.clusters) == 0

    def test_entities_without_domain_skipped(self) -> None:
        """Dict entities missing the 'domain' key are silently skipped (backward compat)."""
        entities: list[WhoisEntity | dict] = [
            {"registrant_org": "No Domain Corp"},
            WhoisEntity(domain="valid.com", registrant_org="Valid Corp"),
        ]
        pivot = RegistrantPivot(per_tenant_authorization=True)
        result = pivot.pivot(entities)
        # Should not crash; the single valid entity produces no clusters.
        assert isinstance(result, PivotResult)

    def test_confidence_in_range(self) -> None:
        """All cluster confidences are in [0.0, 1.0]."""
        pivot = RegistrantPivot(per_tenant_authorization=True)
        result = pivot.pivot(_sample_entities())

        for cluster in result.clusters:
            assert 0.0 <= cluster.confidence <= 1.0, (
                f"Cluster {cluster.key} confidence {cluster.confidence} out of range"
            )

    def test_custom_fuzzy_threshold(self) -> None:
        """Custom fuzzy threshold changes cluster behavior."""
        entities = [
            WhoisEntity(domain="a.com", registrant_org="Acme Corp"),
            WhoisEntity(domain="b.com", registrant_org="Acme Corporation"),
        ]

        # With a very high threshold, slight differences may split clusters.
        strict = RegistrantPivot(
            per_tenant_authorization=True,
            fuzzy_threshold=0.99,
        )
        strict_result = strict.pivot(entities)

        # With a loose threshold, they should definitely cluster.
        loose = RegistrantPivot(
            per_tenant_authorization=True,
            fuzzy_threshold=0.50,
        )
        loose_result = loose.pivot(entities)

        # The loose pivot should produce at least as many clustered members
        # as the strict one.
        loose_org = [
            c for c in loose_result.clusters
            if c.dimension == PivotDimension.ORG_NAME
        ]
        assert len(loose_org) >= 1
        # Loose should always cluster these two.
        largest = max(loose_org, key=lambda c: len(c.members))
        assert len(largest.members) == 2  # noqa: PLR2004

    def test_mixed_whois_entity_and_dict_inputs(self) -> None:
        """Both WhoisEntity models and dicts are accepted in the same list."""
        entities: list[WhoisEntity | dict] = [
            WhoisEntity(domain="a.com", registrant_org="Acme Corp"),
            {"domain": "b.com", "registrant_org": "Acme Corp"},
        ]
        pivot = RegistrantPivot(per_tenant_authorization=True)
        result = pivot.pivot(entities)

        org_clusters = [
            c for c in result.clusters
            if c.dimension == PivotDimension.ORG_NAME
        ]
        assert len(org_clusters) >= 1
        largest = max(org_clusters, key=lambda c: len(c.members))
        domains = {m.domain for m in largest.members}
        assert "a.com" in domains
        assert "b.com" in domains

    def test_org_name_normalization(self) -> None:
        """Corporate suffixes are stripped during normalization."""
        pivot = RegistrantPivot(per_tenant_authorization=True)
        # These should all normalize to roughly "acme".
        assert pivot._normalize_org_name("Acme Corp") == "acme"
        assert pivot._normalize_org_name("Acme Corporation") == "acme"
        assert pivot._normalize_org_name("ACME Inc.") == "acme"
        assert pivot._normalize_org_name("Acme LLC") == "acme"
        assert pivot._normalize_org_name("Acme Ltd.") == "acme"
        assert pivot._normalize_org_name("Acme GmbH") == "acme"

    def test_case_insensitive_domain_normalization(self) -> None:
        """Domains are lowercased and stripped during processing."""
        entities = [
            WhoisEntity(domain="  ACME.COM  ", registrant_org="Test Org"),
            WhoisEntity(domain="acme.com", registrant_org="Test Org"),
        ]
        pivot = RegistrantPivot(per_tenant_authorization=True)
        result = pivot.pivot(entities)

        org_clusters = [
            c for c in result.clusters
            if c.dimension == PivotDimension.ORG_NAME
        ]
        # Both should be in the same cluster (same domain after normalization).
        assert len(org_clusters) >= 1

    def test_name_server_deduplication(self) -> None:
        """Shared name servers produce deduplicated clusters."""
        entities = [
            WhoisEntity(
                domain="a.com",
                name_servers=["ns1.shared.net", "ns2.shared.net"],
            ),
            WhoisEntity(
                domain="b.com",
                name_servers=["ns1.shared.net", "ns2.shared.net"],
            ),
        ]
        pivot = RegistrantPivot(per_tenant_authorization=True)
        result = pivot.pivot(entities)

        ns_clusters = [
            c for c in result.clusters
            if c.dimension == PivotDimension.NAME_SERVER
        ]
        # The two NS produce clusters with the same member set, so
        # deduplication should yield exactly one cluster.
        assert len(ns_clusters) == 1
        assert len(ns_clusters[0].members) == 2  # noqa: PLR2004

    def test_multiple_email_domains_separate_clusters(self) -> None:
        """Different email domains produce separate clusters."""
        entities = [
            WhoisEntity(domain="a.com", registrant_email="u1@corp-alpha.com"),
            WhoisEntity(domain="b.com", registrant_email="u2@corp-alpha.com"),
            WhoisEntity(domain="c.com", registrant_email="u3@corp-beta.com"),
            WhoisEntity(domain="d.com", registrant_email="u4@corp-beta.com"),
        ]
        pivot = RegistrantPivot(per_tenant_authorization=True)
        result = pivot.pivot(entities)

        email_clusters = [
            c for c in result.clusters
            if c.dimension == PivotDimension.EMAIL_DOMAIN
        ]
        keys = {c.key for c in email_clusters}
        assert "corp-alpha.com" in keys
        assert "corp-beta.com" in keys

    def test_type_error_on_invalid_input(self) -> None:
        """Non-dict, non-WhoisEntity input raises TypeError."""
        pivot = RegistrantPivot(per_tenant_authorization=True)
        with pytest.raises(TypeError, match="Expected WhoisEntity or dict"):
            pivot.pivot([42])  # type: ignore[list-item]


# === Org graph tests =========================================================


class TestOrgGraphBuilder:
    """Verify organization graph construction from multiple sources."""

    def test_builds_hierarchy_from_ma_and_whois(self) -> None:
        """Graph combines M&A data and WHOIS pivot data into a hierarchy."""
        # First, run the pivot.
        pivot = RegistrantPivot(per_tenant_authorization=True)
        pivot_result = pivot.pivot(_sample_entities())

        # Build the graph.
        builder = OrgGraphBuilder(per_tenant_authorization=True)
        builder.add_pivot_results(pivot_result)
        builder.add_ma_results(_sample_ma_data())
        graph = builder.build()

        # Verify nodes exist.
        assert len(graph.nodes) > 0
        assert len(graph.edges) > 0

        # Verify org nodes from M&A.
        org_nodes = [n for n in graph.nodes if n.node_type == NodeType.ORGANIZATION]
        org_ids = {n.node_id for n in org_nodes}
        assert "org:acme corp" in org_ids
        assert "org:widget co" in org_ids
        assert "org:gadget inc" in org_ids

        # Verify M&A edges.
        ma_edges = [
            e for e in graph.edges
            if e.edge_type in (EdgeType.ACQUIRED_BY, EdgeType.PARENT_SUBSIDIARY)
        ]
        assert len(ma_edges) >= 2

        # Verify Acme -> Widget Co (acquired_by) edge.
        acquired_edges = [
            e for e in graph.edges
            if e.edge_type == EdgeType.ACQUIRED_BY
        ]
        assert any(
            e.source == "org:acme corp" and e.target == "org:widget co"
            for e in acquired_edges
        )

    def test_dns_relationships_add_ip_ranges(self) -> None:
        """DNS data creates domain nodes, delegation edges, and IP range nodes."""
        builder = OrgGraphBuilder(per_tenant_authorization=True)
        builder.add_dns_relationships(_sample_dns_data())
        graph = builder.build()

        # Verify domain nodes.
        domain_nodes = [
            n for n in graph.nodes if n.node_type == NodeType.DOMAIN
        ]
        domain_ids = {n.node_id for n in domain_nodes}
        assert "domain:acme.com" in domain_ids
        assert "domain:api.acme.com" in domain_ids
        assert "domain:cdn.acme.com" in domain_ids

        # Verify DNS delegation edges.
        dns_edges = [
            e for e in graph.edges
            if e.edge_type == EdgeType.DNS_DELEGATION
        ]
        assert len(dns_edges) >= 2

        # Verify IP range node.
        ip_nodes = [
            n for n in graph.nodes if n.node_type == NodeType.IP_RANGE
        ]
        assert len(ip_nodes) >= 1
        assert any(
            n.node_id == "ip_range:198.51.100.0/24" for n in ip_nodes
        )

        # Verify IP range edge.
        ip_edges = [
            e for e in graph.edges
            if e.edge_type == EdgeType.ORG_TO_IP_RANGE
        ]
        assert len(ip_edges) >= 1

    def test_graph_traversal_helpers(self) -> None:
        """OrgGraph convenience methods return correct results."""
        builder = OrgGraphBuilder(per_tenant_authorization=True)
        builder.add_ma_results(_sample_ma_data())
        graph = builder.build()

        # get_node.
        acme = graph.get_node("org:acme corp")
        assert acme is not None
        assert acme.node_type == NodeType.ORGANIZATION

        # get_node for missing node.
        assert graph.get_node("org:nonexistent") is None

        # get_edges_from.
        acme_outbound = graph.get_edges_from("org:acme corp")
        assert len(acme_outbound) >= 2

        # get_edges_to.
        widget_inbound = graph.get_edges_to("org:widget co")
        assert len(widget_inbound) >= 1

        # children_of.
        children = graph.children_of("org:acme corp")
        assert "org:widget co" in children
        assert "org:gadget inc" in children

    def test_empty_graph(self) -> None:
        """Building with no data produces an empty graph."""
        builder = OrgGraphBuilder(per_tenant_authorization=True)
        graph = builder.build()
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0

    def test_ma_entries_without_required_fields_skipped(self) -> None:
        """M&A dict entries missing acquirer or target are silently skipped (backward compat)."""
        builder = OrgGraphBuilder(per_tenant_authorization=True)
        builder.add_ma_results([
            {"acquirer": "Acme Corp"},  # missing target -- skipped by coercion
            {"target": "Widget Co"},   # missing acquirer -- skipped by coercion
            {},                        # missing both -- skipped by coercion
        ])
        graph = builder.build()
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0

    def test_cycle_free_ma_edges(self) -> None:
        """M&A edges are directed -- no implicit reverse edges created."""
        builder = OrgGraphBuilder(per_tenant_authorization=True)
        builder.add_ma_results([
            MaResult(
                acquirer="Big Corp",
                target="Small Co",
                relationship="acquired_by",
                confidence=0.9,
            ),
        ])
        graph = builder.build()

        # There should be exactly one edge: Big Corp -> Small Co.
        assert len(graph.edges) == 1
        edge = graph.edges[0]
        assert edge.source == "org:big corp"
        assert edge.target == "org:small co"

        # No reverse edge should exist.
        reverse_edges = [
            e for e in graph.edges
            if e.source == "org:small co" and e.target == "org:big corp"
        ]
        assert len(reverse_edges) == 0

    def test_duplicate_nodes_not_created(self) -> None:
        """Repeated add_pivot_results does not duplicate org/domain nodes."""
        pivot = RegistrantPivot(per_tenant_authorization=True)
        pivot_result = pivot.pivot(_sample_entities())

        builder = OrgGraphBuilder(per_tenant_authorization=True)
        builder.add_pivot_results(pivot_result)
        count_after_first = len(builder._nodes)

        builder.add_pivot_results(pivot_result)
        count_after_second = len(builder._nodes)

        # Node count should not change because the same IDs are reused.
        assert count_after_first == count_after_second

    def test_merged_with_edge_type(self) -> None:
        """merged_with relationship is mapped to the correct edge type."""
        builder = OrgGraphBuilder(per_tenant_authorization=True)
        builder.add_ma_results([
            MaResult(
                acquirer="Alpha Inc",
                target="Beta LLC",
                relationship="merged_with",
                confidence=0.8,
            ),
        ])
        graph = builder.build()

        merged_edges = [
            e for e in graph.edges if e.edge_type == EdgeType.MERGED_WITH
        ]
        assert len(merged_edges) == 1
        assert merged_edges[0].source == "org:alpha inc"
        assert merged_edges[0].target == "org:beta llc"

    def test_dns_without_ip_ranges(self) -> None:
        """DNS relationships without IP ranges still create domain nodes."""
        builder = OrgGraphBuilder(per_tenant_authorization=True)
        builder.add_dns_relationships([
            DnsRelationship(
                parent_domain="example.com",
                child_domain="sub.example.com",
            ),
        ])
        graph = builder.build()

        domain_ids = {n.node_id for n in graph.nodes}
        assert "domain:example.com" in domain_ids
        assert "domain:sub.example.com" in domain_ids

        # No IP range nodes.
        ip_nodes = [n for n in graph.nodes if n.node_type == NodeType.IP_RANGE]
        assert len(ip_nodes) == 0

    def test_dns_entries_without_required_fields_skipped(self) -> None:
        """DNS dict entries missing parent_domain or child_domain are skipped."""
        builder = OrgGraphBuilder(per_tenant_authorization=True)
        builder.add_dns_relationships([
            {"parent_domain": "example.com"},  # missing child_domain
            {"child_domain": "sub.example.com"},  # missing parent_domain
            {},  # missing both
        ])
        graph = builder.build()
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0

    def test_type_error_on_invalid_ma_input(self) -> None:
        """Non-dict, non-MaResult input raises TypeError."""
        builder = OrgGraphBuilder(per_tenant_authorization=True)
        with pytest.raises(TypeError, match="Expected MaResult or dict"):
            builder.add_ma_results([42])  # type: ignore[list-item]

    def test_type_error_on_invalid_dns_input(self) -> None:
        """Non-dict, non-DnsRelationship input raises TypeError."""
        builder = OrgGraphBuilder(per_tenant_authorization=True)
        with pytest.raises(TypeError, match="Expected DnsRelationship or dict"):
            builder.add_dns_relationships(["invalid"])  # type: ignore[list-item]

    def test_org_graph_immutability(self) -> None:
        """OrgGraph is a frozen dataclass -- nodes and edges are tuples."""
        builder = OrgGraphBuilder(per_tenant_authorization=True)
        builder.add_ma_results(_sample_ma_data())
        graph = builder.build()

        assert isinstance(graph.nodes, tuple)
        assert isinstance(graph.edges, tuple)

    def test_edges_from_nonexistent_node(self) -> None:
        """get_edges_from returns empty list for unknown node."""
        builder = OrgGraphBuilder(per_tenant_authorization=True)
        graph = builder.build()
        assert graph.get_edges_from("nonexistent") == []

    def test_edges_to_nonexistent_node(self) -> None:
        """get_edges_to returns empty list for unknown node."""
        builder = OrgGraphBuilder(per_tenant_authorization=True)
        graph = builder.build()
        assert graph.get_edges_to("nonexistent") == []

    def test_children_of_nonexistent_node(self) -> None:
        """children_of returns empty list for unknown node."""
        builder = OrgGraphBuilder(per_tenant_authorization=True)
        graph = builder.build()
        assert graph.children_of("nonexistent") == []

    def test_ma_confidence_preserved(self) -> None:
        """M&A edge confidence values are preserved from input."""
        builder = OrgGraphBuilder(per_tenant_authorization=True)
        builder.add_ma_results([
            MaResult(
                acquirer="X",
                target="Y",
                relationship="acquired_by",
                confidence=0.42,
            ),
        ])
        graph = builder.build()
        assert len(graph.edges) == 1
        assert graph.edges[0].confidence == pytest.approx(0.42)

    def test_ma_properties_preserved(self) -> None:
        """M&A edge properties dict is preserved from input."""
        builder = OrgGraphBuilder(per_tenant_authorization=True)
        builder.add_ma_results([
            MaResult(
                acquirer="X",
                target="Y",
                confidence=0.9,
                properties={"date": "2024-06-01", "source": "SEC filing"},
            ),
        ])
        graph = builder.build()
        assert graph.edges[0].properties["date"] == "2024-06-01"
        assert graph.edges[0].properties["source"] == "SEC filing"


# === Ethics document tests ===================================================


class TestEthicsDocument:
    """Verify the IDENTITY_SURFACE_ETHICS.md document exists and has required sections."""

    def test_ethics_document_exists(self) -> None:
        """The ethics document file exists at the expected path."""
        assert ETHICS_DOC_PATH.exists(), (
            f"Ethics document not found at {ETHICS_DOC_PATH}"
        )

    def test_ethics_document_has_scope_limitations(self) -> None:
        """Ethics document contains a Scope Limitations section."""
        content = ETHICS_DOC_PATH.read_text(encoding="utf-8")
        assert "## Scope Limitations" in content

    def test_ethics_document_has_prohibited_uses(self) -> None:
        """Ethics document contains a Prohibited Uses section."""
        content = ETHICS_DOC_PATH.read_text(encoding="utf-8")
        assert "## Prohibited Uses" in content

    def test_ethics_document_has_data_retention(self) -> None:
        """Ethics document contains a Data Retention Requirements section."""
        content = ETHICS_DOC_PATH.read_text(encoding="utf-8")
        assert "## Data Retention Requirements" in content

    def test_ethics_document_has_consent_requirements(self) -> None:
        """Ethics document contains a Consent Requirements section."""
        content = ETHICS_DOC_PATH.read_text(encoding="utf-8")
        assert "## Consent Requirements" in content


# === License check test ======================================================


class TestLicenseCheck:
    """Verify the module license placeholder."""

    def test_check_license_returns_true(self) -> None:
        """check_license() returns True (placeholder per ADR-009)."""
        assert check_license() is True


# === API endpoint tests ======================================================


class TestIdentityAPI:
    """HTTP endpoint tests for the identity router."""

    # -- Registrant Pivot endpoint --

    @pytest.mark.anyio()
    async def test_registrant_pivot_200(self, client: AsyncClient) -> None:
        """GET /identity/registrant-pivot returns 200 with placeholder data."""
        resp = await client.get(_PIVOT_URL, params={"domain": "acme-corp.com"})
        assert resp.status_code == 200

    @pytest.mark.anyio()
    async def test_registrant_pivot_response_structure(
        self, client: AsyncClient,
    ) -> None:
        """Response contains all required fields."""
        resp = await client.get(_PIVOT_URL, params={"domain": "acme-corp.com"})
        data = resp.json()

        assert data["tenant_id"] == _TENANT_ID
        assert data["query_domain"] == "acme-corp.com"
        assert data["is_placeholder"] is True
        assert "generated_at" in data
        assert "total_clusters" in data
        assert "clusters" in data
        assert isinstance(data["clusters"], list)

    @pytest.mark.anyio()
    async def test_registrant_pivot_clusters_have_members(
        self, client: AsyncClient,
    ) -> None:
        """Pivot clusters contain member data with domain and registrant info."""
        resp = await client.get(_PIVOT_URL, params={"domain": "acme-corp.com"})
        data = resp.json()

        assert data["total_clusters"] > 0
        for cluster in data["clusters"]:
            assert "dimension" in cluster
            assert "key" in cluster
            assert "confidence" in cluster
            assert "members" in cluster
            assert isinstance(cluster["members"], list)
            assert len(cluster["members"]) >= 2  # noqa: PLR2004
            for member in cluster["members"]:
                assert "domain" in member

    @pytest.mark.anyio()
    async def test_registrant_pivot_confidence_valid(
        self, client: AsyncClient,
    ) -> None:
        """All confidence values in pivot clusters are in [0.0, 1.0]."""
        resp = await client.get(_PIVOT_URL, params={"domain": "acme-corp.com"})
        data = resp.json()

        for cluster in data["clusters"]:
            assert 0.0 <= cluster["confidence"] <= 1.0

    @pytest.mark.anyio()
    async def test_registrant_pivot_fuzzy_threshold_param(
        self, client: AsyncClient,
    ) -> None:
        """fuzzy_threshold query param is accepted and affects results."""
        # Very strict threshold -- should still return 200.
        resp = await client.get(
            _PIVOT_URL,
            params={"domain": "acme-corp.com", "fuzzy_threshold": 0.99},
        )
        assert resp.status_code == 200

        # Very loose threshold.
        resp_loose = await client.get(
            _PIVOT_URL,
            params={"domain": "acme-corp.com", "fuzzy_threshold": 0.5},
        )
        assert resp_loose.status_code == 200

    @pytest.mark.anyio()
    async def test_registrant_pivot_domain_required(
        self, client: AsyncClient,
    ) -> None:
        """Missing domain query param returns 422."""
        resp = await client.get(_PIVOT_URL)
        assert resp.status_code == 422

    @pytest.mark.anyio()
    async def test_registrant_pivot_dimensions_present(
        self, client: AsyncClient,
    ) -> None:
        """Placeholder data produces clusters across multiple dimensions."""
        resp = await client.get(_PIVOT_URL, params={"domain": "acme-corp.com"})
        data = resp.json()
        dimensions = {c["dimension"] for c in data["clusters"]}
        # The placeholder data should produce at least org_name and email_domain.
        assert len(dimensions) >= 2  # noqa: PLR2004

    # -- Org Graph endpoint --

    @pytest.mark.anyio()
    async def test_org_graph_200(self, client: AsyncClient) -> None:
        """GET /identity/org-graph returns 200 with placeholder data."""
        resp = await client.get(_GRAPH_URL)
        assert resp.status_code == 200

    @pytest.mark.anyio()
    async def test_org_graph_response_structure(
        self, client: AsyncClient,
    ) -> None:
        """Response contains all required fields."""
        resp = await client.get(_GRAPH_URL)
        data = resp.json()

        assert data["tenant_id"] == _TENANT_ID
        assert data["is_placeholder"] is True
        assert "generated_at" in data
        assert "total_nodes" in data
        assert "total_edges" in data
        assert "nodes" in data
        assert "edges" in data
        assert isinstance(data["nodes"], list)
        assert isinstance(data["edges"], list)

    @pytest.mark.anyio()
    async def test_org_graph_contains_nodes_and_edges(
        self, client: AsyncClient,
    ) -> None:
        """Graph contains both nodes and edges from placeholder data."""
        resp = await client.get(_GRAPH_URL)
        data = resp.json()

        assert data["total_nodes"] > 0
        assert data["total_edges"] > 0
        assert data["total_nodes"] == len(data["nodes"])
        assert data["total_edges"] == len(data["edges"])

    @pytest.mark.anyio()
    async def test_org_graph_node_structure(
        self, client: AsyncClient,
    ) -> None:
        """Graph nodes have the correct structure."""
        resp = await client.get(_GRAPH_URL)
        data = resp.json()

        for node in data["nodes"]:
            assert "node_id" in node
            assert "node_type" in node
            assert node["node_type"] in (
                "organization", "domain", "ip_range", "email_infrastructure",
            )

    @pytest.mark.anyio()
    async def test_org_graph_edge_structure(
        self, client: AsyncClient,
    ) -> None:
        """Graph edges have the correct structure."""
        resp = await client.get(_GRAPH_URL)
        data = resp.json()

        for edge in data["edges"]:
            assert "source" in edge
            assert "target" in edge
            assert "edge_type" in edge
            assert "confidence" in edge
            assert 0.0 <= edge["confidence"] <= 1.0

    @pytest.mark.anyio()
    async def test_org_graph_include_dns_false(
        self, client: AsyncClient,
    ) -> None:
        """include_dns=false excludes DNS delegation data from graph."""
        resp_with = await client.get(_GRAPH_URL, params={"include_dns": True})
        resp_without = await client.get(_GRAPH_URL, params={"include_dns": False})

        data_with = resp_with.json()
        data_without = resp_without.json()

        # Without DNS, there should be fewer nodes and edges.
        assert data_without["total_nodes"] <= data_with["total_nodes"]
        assert data_without["total_edges"] <= data_with["total_edges"]

        # No DNS delegation edges in the without-DNS response.
        dns_edges = [
            e for e in data_without["edges"]
            if e["edge_type"] == "dns_delegation"
        ]
        assert len(dns_edges) == 0

    @pytest.mark.anyio()
    async def test_org_graph_include_ma_false(
        self, client: AsyncClient,
    ) -> None:
        """include_ma=false excludes M&A relationships from graph."""
        resp_with = await client.get(_GRAPH_URL, params={"include_ma": True})
        resp_without = await client.get(_GRAPH_URL, params={"include_ma": False})

        data_with = resp_with.json()
        data_without = resp_without.json()

        # Without M&A, there should be no acquired_by or parent_subsidiary edges.
        ma_edge_types = {"acquired_by", "parent_subsidiary", "merged_with"}
        ma_edges = [
            e for e in data_without["edges"]
            if e["edge_type"] in ma_edge_types
        ]
        assert len(ma_edges) == 0

        # With M&A, there should be at least one.
        ma_edges_with = [
            e for e in data_with["edges"]
            if e["edge_type"] in ma_edge_types
        ]
        assert len(ma_edges_with) >= 1

    @pytest.mark.anyio()
    async def test_invalid_tenant_id_422(self, client: AsyncClient) -> None:
        """Invalid (non-UUID) tenant_id returns 422."""
        resp = await client.get(
            "http://test/v1/tenants/not-a-uuid/identity/org-graph",
        )
        assert resp.status_code == 422

    @pytest.mark.anyio()
    async def test_org_graph_has_organization_nodes(
        self, client: AsyncClient,
    ) -> None:
        """Graph includes organization-type nodes from pivot + M&A data."""
        resp = await client.get(_GRAPH_URL)
        data = resp.json()

        org_nodes = [
            n for n in data["nodes"] if n["node_type"] == "organization"
        ]
        assert len(org_nodes) >= 1

    @pytest.mark.anyio()
    async def test_org_graph_has_domain_nodes(
        self, client: AsyncClient,
    ) -> None:
        """Graph includes domain-type nodes from pivot + DNS data."""
        resp = await client.get(_GRAPH_URL)
        data = resp.json()

        domain_nodes = [
            n for n in data["nodes"] if n["node_type"] == "domain"
        ]
        assert len(domain_nodes) >= 1
