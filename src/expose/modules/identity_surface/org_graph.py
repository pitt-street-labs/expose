"""Organization graph builder: directed graph of org relationships.

Builds a directed graph from registrant pivot results, M&A discovery
data, and DNS relationship data. Nodes represent organizations; edges
represent typed relationships (parent/subsidiary, org-to-domain,
org-to-IP-range, org-to-email-infrastructure).

Ethics gate: operations are refused unless ``per_tenant_authorization=True``.
"""

from __future__ import annotations

# Copyright 2026 Korlogos / Pitt Street Labs. All rights reserved.
# This file is part of EXPOSE Commercial Modules and is NOT covered by the
# Apache 2.0 license that governs the core engine. Unauthorized copying,
# distribution, or use of this file is strictly prohibited. Contact
# licensing@korlogos.com for commercial licensing terms.

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from pydantic import BaseModel

from expose.modules.identity_surface.registrant_pivot import (
    AuthorizationError,
    PivotResult,
)


class MaResult(BaseModel):
    """Typed model for M&A (mergers and acquisitions) discovery input.

    Replaces ``dict[str, Any]`` inputs to
    ``OrgGraphBuilder.add_ma_results()`` for type safety. Legacy dict
    inputs are still accepted via ``model_validate()`` for backward
    compatibility.
    """

    acquirer: str
    target: str
    relationship: str = "acquired_by"
    confidence: float = 0.7
    properties: dict[str, Any] = {}


class DnsRelationship(BaseModel):
    """Typed model for DNS relationship input data.

    Replaces ``dict[str, Any]`` inputs to
    ``OrgGraphBuilder.add_dns_relationships()`` for type safety. Legacy
    dict inputs are still accepted via ``model_validate()`` for backward
    compatibility.
    """

    parent_domain: str
    child_domain: str
    relationship: str = "dns_delegation"
    confidence: float = 0.6
    ip_ranges: list[str] = []


class NodeType(StrEnum):
    """Type of node in the organization graph."""

    ORGANIZATION = "organization"
    DOMAIN = "domain"
    IP_RANGE = "ip_range"
    EMAIL_INFRASTRUCTURE = "email_infrastructure"


class EdgeType(StrEnum):
    """Type of relationship edge in the organization graph."""

    PARENT_SUBSIDIARY = "parent_subsidiary"
    ORG_TO_DOMAIN = "org_to_domain"
    ORG_TO_IP_RANGE = "org_to_ip_range"
    ORG_TO_EMAIL = "org_to_email"
    ACQUIRED_BY = "acquired_by"
    MERGED_WITH = "merged_with"
    DNS_DELEGATION = "dns_delegation"


@dataclass(frozen=True)
class GraphNode:
    """A node in the organization graph.

    ``node_id`` is a stable identifier (typically the canonical name or
    address).  ``node_type`` classifies the node.  ``properties`` holds
    arbitrary metadata sourced from the input data.
    """

    node_id: str
    node_type: NodeType
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class GraphEdge:
    """A directed edge in the organization graph.

    ``source`` and ``target`` are ``node_id`` values.  ``edge_type``
    classifies the relationship.  ``confidence`` is in [0.0, 1.0].
    ``properties`` holds relationship metadata (e.g., acquisition date).
    """

    source: str
    target: str
    edge_type: EdgeType
    confidence: float
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class OrgGraph:
    """Directed graph of organizational relationships.

    ``nodes`` and ``edges`` are the full graph.  Convenience methods
    provide traversal helpers.
    """

    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]

    def get_node(self, node_id: str) -> GraphNode | None:
        """Return the node with ``node_id``, or ``None`` if not found."""
        for node in self.nodes:
            if node.node_id == node_id:
                return node
        return None

    def get_edges_from(self, node_id: str) -> list[GraphEdge]:
        """Return all edges originating from ``node_id``."""
        return [e for e in self.edges if e.source == node_id]

    def get_edges_to(self, node_id: str) -> list[GraphEdge]:
        """Return all edges terminating at ``node_id``."""
        return [e for e in self.edges if e.target == node_id]

    def children_of(self, node_id: str) -> list[str]:
        """Return target node IDs for all edges from ``node_id``."""
        return [e.target for e in self.get_edges_from(node_id)]


def _coerce_ma_results(
    data: list[MaResult | dict[str, Any]],
) -> list[MaResult]:
    """Coerce a mixed list of ``MaResult`` models and dicts.

    Dict entries are validated via ``MaResult.model_validate()``.
    Dicts missing required ``acquirer`` or ``target`` keys are silently
    skipped (matching the previous behavior).
    """
    result: list[MaResult] = []
    for entry in data:
        if isinstance(entry, MaResult):
            result.append(entry)
        elif isinstance(entry, dict):
            if not entry.get("acquirer") or not entry.get("target"):
                continue
            result.append(MaResult.model_validate(entry))
        else:
            raise TypeError(
                f"Expected MaResult or dict, got {type(entry).__name__}"
            )
    return result


def _coerce_dns_relationships(
    data: list[DnsRelationship | dict[str, Any]],
) -> list[DnsRelationship]:
    """Coerce a mixed list of ``DnsRelationship`` models and dicts.

    Dict entries are validated via ``DnsRelationship.model_validate()``.
    Dicts missing required ``parent_domain`` or ``child_domain`` keys
    are silently skipped (matching the previous behavior).
    """
    result: list[DnsRelationship] = []
    for entry in data:
        if isinstance(entry, DnsRelationship):
            result.append(entry)
        elif isinstance(entry, dict):
            if not entry.get("parent_domain") or not entry.get("child_domain"):
                continue
            result.append(DnsRelationship.model_validate(entry))
        else:
            raise TypeError(
                f"Expected DnsRelationship or dict, got {type(entry).__name__}"
            )
    return result


class OrgGraphBuilder:
    """Build an organization graph from multiple data sources.

    Parameters
    ----------
    per_tenant_authorization:
        Must be ``True`` to enable operations. When ``False`` (the default),
        all builder methods raise ``AuthorizationError``.
    """

    def __init__(
        self,
        *,
        per_tenant_authorization: bool = False,
    ) -> None:
        self._authorized = per_tenant_authorization
        self._nodes: dict[str, GraphNode] = {}
        self._edges: list[GraphEdge] = []

    def _require_auth(self) -> None:
        """Raise ``AuthorizationError`` if not authorized."""
        if not self._authorized:
            raise AuthorizationError(
                "Identity Surface operations require per_tenant_authorization=True. "
                "See IDENTITY_SURFACE_ETHICS.md for consent and scope requirements."
            )

    # ------------------------------------------------------------------
    # Data ingestion
    # ------------------------------------------------------------------

    def add_pivot_results(self, pivot: PivotResult) -> None:
        """Ingest registrant pivot clusters into the graph.

        Creates organization nodes from cluster keys and domain nodes
        from cluster members. Adds ``ORG_TO_DOMAIN`` edges linking each
        org to its domains.

        Raises
        ------
        AuthorizationError
            If ``per_tenant_authorization`` was not set to ``True``.
        """
        self._require_auth()

        for cluster in pivot.clusters:
            # Create or update the org node.
            org_id = f"org:{cluster.key}"
            if org_id not in self._nodes:
                self._nodes[org_id] = GraphNode(
                    node_id=org_id,
                    node_type=NodeType.ORGANIZATION,
                    properties={
                        "name": cluster.key,
                        "pivot_dimension": str(cluster.dimension),
                    },
                )

            # Create domain nodes and edges.
            for member in cluster.members:
                domain_id = f"domain:{member.domain}"
                if domain_id not in self._nodes:
                    self._nodes[domain_id] = GraphNode(
                        node_id=domain_id,
                        node_type=NodeType.DOMAIN,
                        properties={"domain": member.domain},
                    )
                self._edges.append(
                    GraphEdge(
                        source=org_id,
                        target=domain_id,
                        edge_type=EdgeType.ORG_TO_DOMAIN,
                        confidence=cluster.confidence,
                    )
                )

    def add_ma_results(
        self, ma_data: list[MaResult | dict[str, Any]]
    ) -> None:
        """Ingest M&A (mergers and acquisitions) discovery results.

        Each entry should be an ``MaResult`` model (preferred) or a dict
        with keys: ``acquirer`` (str), ``target`` (str),
        ``relationship`` (str, one of ``"acquired_by"``,
        ``"merged_with"``, ``"parent_subsidiary"``), and optionally
        ``confidence`` (float, default 0.7) and ``properties`` (dict).
        Dict inputs are coerced via ``MaResult.model_validate()`` for
        backward compatibility.

        Raises
        ------
        AuthorizationError
            If ``per_tenant_authorization`` was not set to ``True``.
        """
        self._require_auth()

        validated = _coerce_ma_results(ma_data)

        _RELATIONSHIP_MAP = {
            "acquired_by": EdgeType.ACQUIRED_BY,
            "merged_with": EdgeType.MERGED_WITH,
            "parent_subsidiary": EdgeType.PARENT_SUBSIDIARY,
        }

        for entry in validated:
            acquirer_id = f"org:{entry.acquirer.lower().strip()}"
            target_id = f"org:{entry.target.lower().strip()}"

            for node_id, name in [
                (acquirer_id, entry.acquirer),
                (target_id, entry.target),
            ]:
                if node_id not in self._nodes:
                    self._nodes[node_id] = GraphNode(
                        node_id=node_id,
                        node_type=NodeType.ORGANIZATION,
                        properties={"name": name},
                    )

            edge_type = _RELATIONSHIP_MAP.get(
                entry.relationship, EdgeType.PARENT_SUBSIDIARY
            )

            self._edges.append(
                GraphEdge(
                    source=acquirer_id,
                    target=target_id,
                    edge_type=edge_type,
                    confidence=entry.confidence,
                    properties=dict(entry.properties),
                )
            )

    def add_dns_relationships(
        self, dns_data: list[DnsRelationship | dict[str, Any]]
    ) -> None:
        """Ingest DNS relationship data (e.g., NS delegation chains).

        Each entry should be a ``DnsRelationship`` model (preferred) or
        a dict with keys: ``parent_domain`` (str), ``child_domain``
        (str), and optionally ``relationship`` (str, default
        ``"dns_delegation"``), ``confidence`` (float, default 0.6), and
        ``ip_ranges`` (list of str). Dict inputs are coerced via
        ``DnsRelationship.model_validate()`` for backward compatibility.

        IP ranges are added as ``IP_RANGE`` nodes with ``ORG_TO_IP_RANGE``
        edges if a parent org node exists.

        Raises
        ------
        AuthorizationError
            If ``per_tenant_authorization`` was not set to ``True``.
        """
        self._require_auth()

        validated = _coerce_dns_relationships(dns_data)

        for entry in validated:
            parent_id = f"domain:{entry.parent_domain.lower().strip()}"
            child_id = f"domain:{entry.child_domain.lower().strip()}"

            for domain_id, domain_name in [
                (parent_id, entry.parent_domain),
                (child_id, entry.child_domain),
            ]:
                if domain_id not in self._nodes:
                    self._nodes[domain_id] = GraphNode(
                        node_id=domain_id,
                        node_type=NodeType.DOMAIN,
                        properties={"domain": domain_name},
                    )

            self._edges.append(
                GraphEdge(
                    source=parent_id,
                    target=child_id,
                    edge_type=EdgeType.DNS_DELEGATION,
                    confidence=entry.confidence,
                )
            )

            # Add IP range nodes if provided.
            for ip_range in entry.ip_ranges:
                ip_id = f"ip_range:{ip_range}"
                if ip_id not in self._nodes:
                    self._nodes[ip_id] = GraphNode(
                        node_id=ip_id,
                        node_type=NodeType.IP_RANGE,
                        properties={"range": ip_range},
                    )
                # Link from the parent domain to the IP range.
                self._edges.append(
                    GraphEdge(
                        source=parent_id,
                        target=ip_id,
                        edge_type=EdgeType.ORG_TO_IP_RANGE,
                        confidence=entry.confidence,
                    )
                )

    # ------------------------------------------------------------------
    # Build output
    # ------------------------------------------------------------------

    def build(self) -> OrgGraph:
        """Construct and return the immutable ``OrgGraph``.

        Raises
        ------
        AuthorizationError
            If ``per_tenant_authorization`` was not set to ``True``.
        """
        self._require_auth()

        return OrgGraph(
            nodes=tuple(self._nodes.values()),
            edges=tuple(self._edges),
        )


__all__ = [
    "DnsRelationship",
    "EdgeType",
    "GraphEdge",
    "GraphNode",
    "MaResult",
    "NodeType",
    "OrgGraph",
    "OrgGraphBuilder",
]
