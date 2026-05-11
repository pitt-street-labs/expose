"""Tests for the EXPOSE Identity Surface module.

Coverage:
    1. Registrant pivot groups domains by org name
    2. Fuzzy matching handles name variations ("Acme Corp" vs "ACME Corporation")
    3. Registrant pivot groups by email domain
    4. Registrant pivot groups by address (city + country)
    5. Registrant pivot groups by name server patterns
    6. Single-member groups are excluded (no self-clusters)
    7. Free email providers are excluded from email-domain pivots
    8. Org graph builds hierarchy from M&A + WHOIS pivot data
    9. Org graph ingests DNS relationship data with IP ranges
   10. Ethics gate blocks RegistrantPivot when per_tenant_authorization=False
   11. Ethics gate blocks OrgGraphBuilder when per_tenant_authorization=False
   12. Ethics gate allows RegistrantPivot when per_tenant_authorization=True
   13. Ethics gate allows OrgGraphBuilder when per_tenant_authorization=True
   14. Ethics document exists with required sections
   15. Module check_license() returns True (placeholder)
   16. OrgGraph traversal helpers work correctly
"""

from __future__ import annotations

from pathlib import Path

import pytest

from expose.modules.identity_surface import check_license
from expose.modules.identity_surface.org_graph import (
    EdgeType,
    NodeType,
    OrgGraph,
    OrgGraphBuilder,
)
from expose.modules.identity_surface.registrant_pivot import (
    AuthorizationError,
    PivotDimension,
    PivotResult,
    RegistrantPivot,
)


# === Fixtures ================================================================

ETHICS_DOC_PATH = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "expose"
    / "modules"
    / "identity_surface"
    / "IDENTITY_SURFACE_ETHICS.md"
)


def _sample_entities() -> list[dict]:
    """Return a representative set of WHOIS entity dicts for testing."""
    return [
        {
            "domain": "acme.com",
            "registrant_org": "Acme Corp",
            "registrant_email": "domains@acme.com",
            "registrant_city": "San Francisco",
            "registrant_country": "US",
            "name_servers": ["ns1.acmedns.net", "ns2.acmedns.net"],
        },
        {
            "domain": "acme.net",
            "registrant_org": "ACME Corporation",
            "registrant_email": "admin@acme.com",
            "registrant_city": "San Francisco",
            "registrant_country": "US",
            "name_servers": ["ns1.acmedns.net", "ns2.acmedns.net"],
        },
        {
            "domain": "acme-labs.io",
            "registrant_org": "Acme Corp",
            "registrant_email": "hostmaster@acme.com",
            "registrant_city": "San Francisco",
            "registrant_country": "US",
            "name_servers": ["ns1.acmedns.net", "ns2.acmedns.net"],
        },
        {
            "domain": "globex.com",
            "registrant_org": "Globex Corporation",
            "registrant_email": "dns@globex.com",
            "registrant_city": "New York",
            "registrant_country": "US",
            "name_servers": ["ns1.globexdns.com", "ns2.globexdns.com"],
        },
        {
            "domain": "globex.io",
            "registrant_org": "Globex Corp",
            "registrant_email": "admin@globex.com",
            "registrant_city": "New York",
            "registrant_country": "US",
            "name_servers": ["ns1.globexdns.com", "ns2.globexdns.com"],
        },
    ]


def _sample_ma_data() -> list[dict]:
    """Return M&A discovery entries for testing."""
    return [
        {
            "acquirer": "Acme Corp",
            "target": "Widget Co",
            "relationship": "acquired_by",
            "confidence": 0.9,
            "properties": {"date": "2024-01-15"},
        },
        {
            "acquirer": "Acme Corp",
            "target": "Gadget Inc",
            "relationship": "parent_subsidiary",
            "confidence": 0.85,
        },
    ]


def _sample_dns_data() -> list[dict]:
    """Return DNS relationship entries for testing."""
    return [
        {
            "parent_domain": "acme.com",
            "child_domain": "api.acme.com",
            "relationship": "dns_delegation",
            "confidence": 0.9,
            "ip_ranges": ["198.51.100.0/24"],
        },
        {
            "parent_domain": "acme.com",
            "child_domain": "cdn.acme.com",
            "confidence": 0.8,
        },
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
            {"domain": "a.com", "registrant_org": "Acme Corp"},
            {"domain": "b.com", "registrant_org": "ACME Corporation"},
            {"domain": "c.com", "registrant_org": "Acme Corp."},
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
            {"domain": "a.com", "registrant_org": "Acme Corp"},
            {"domain": "b.com", "registrant_org": "Totally Different LLC"},
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
            {"domain": "a.com", "registrant_email": "user1@gmail.com"},
            {"domain": "b.com", "registrant_email": "user2@gmail.com"},
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
            {
                "domain": "solo.com",
                "registrant_org": "UniqueOrg XYZ",
                "registrant_email": "admin@unique-org-xyz.com",
                "registrant_city": "Timbuktu",
                "registrant_country": "ML",
                "name_servers": ["ns.unique.example"],
            },
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
        """Entities missing the 'domain' key are silently skipped."""
        entities = [
            {"registrant_org": "No Domain Corp"},
            {"domain": "valid.com", "registrant_org": "Valid Corp"},
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
        """M&A entries missing acquirer or target are silently skipped."""
        builder = OrgGraphBuilder(per_tenant_authorization=True)
        builder.add_ma_results([
            {"acquirer": "Acme Corp"},  # missing target
            {"target": "Widget Co"},   # missing acquirer
            {},                        # missing both
        ])
        graph = builder.build()
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0


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
