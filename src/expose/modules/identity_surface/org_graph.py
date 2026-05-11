"""Organization graph builder: directed graph of org relationships.

Builds a directed graph from registrant pivot results, M&A discovery
data, and DNS relationship data. Nodes represent organizations; edges
represent typed relationships (parent/subsidiary, org-to-domain,
org-to-IP-range, org-to-email-infrastructure).

Ethics gate: operations are refused unless ``per_tenant_authorization=True``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from expose.modules.identity_surface.registrant_pivot import (
    AuthorizationError,
    PivotResult,
)


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

    def add_ma_results(self, ma_data: list[dict[str, Any]]) -> None:
        """Ingest M&A (mergers and acquisitions) discovery results.

        Each entry should have:
        ``acquirer`` (str), ``target`` (str), ``relationship`` (str,
        one of ``"acquired_by"``, ``"merged_with"``, ``"parent_subsidiary"``),
        and optionally ``confidence`` (float, default 0.7) and
        ``properties`` (dict).

        Raises
        ------
        AuthorizationError
            If ``per_tenant_authorization`` was not set to ``True``.
        """
        self._require_auth()

        _RELATIONSHIP_MAP = {
            "acquired_by": EdgeType.ACQUIRED_BY,
            "merged_with": EdgeType.MERGED_WITH,
            "parent_subsidiary": EdgeType.PARENT_SUBSIDIARY,
        }

        for entry in ma_data:
            acquirer = entry.get("acquirer")
            target = entry.get("target")
            relationship = entry.get("relationship", "parent_subsidiary")

            if not acquirer or not target:
                continue

            acquirer_id = f"org:{acquirer.lower().strip()}"
            target_id = f"org:{target.lower().strip()}"

            for node_id, name in [
                (acquirer_id, acquirer),
                (target_id, target),
            ]:
                if node_id not in self._nodes:
                    self._nodes[node_id] = GraphNode(
                        node_id=node_id,
                        node_type=NodeType.ORGANIZATION,
                        properties={"name": name},
                    )

            edge_type = _RELATIONSHIP_MAP.get(
                relationship, EdgeType.PARENT_SUBSIDIARY
            )
            confidence = float(entry.get("confidence", 0.7))
            props = dict(entry.get("properties", {}))

            self._edges.append(
                GraphEdge(
                    source=acquirer_id,
                    target=target_id,
                    edge_type=edge_type,
                    confidence=confidence,
                    properties=props,
                )
            )

    def add_dns_relationships(
        self, dns_data: list[dict[str, Any]]
    ) -> None:
        """Ingest DNS relationship data (e.g., NS delegation chains).

        Each entry should have:
        ``parent_domain`` (str), ``child_domain`` (str), and optionally
        ``relationship`` (str, default ``"dns_delegation"``),
        ``confidence`` (float, default 0.6), and ``ip_ranges`` (list of str).

        IP ranges are added as ``IP_RANGE`` nodes with ``ORG_TO_IP_RANGE``
        edges if a parent org node exists.

        Raises
        ------
        AuthorizationError
            If ``per_tenant_authorization`` was not set to ``True``.
        """
        self._require_auth()

        for entry in dns_data:
            parent = entry.get("parent_domain")
            child = entry.get("child_domain")

            if not parent or not child:
                continue

            parent_id = f"domain:{parent.lower().strip()}"
            child_id = f"domain:{child.lower().strip()}"

            for domain_id, domain_name in [
                (parent_id, parent),
                (child_id, child),
            ]:
                if domain_id not in self._nodes:
                    self._nodes[domain_id] = GraphNode(
                        node_id=domain_id,
                        node_type=NodeType.DOMAIN,
                        properties={"domain": domain_name},
                    )

            confidence = float(entry.get("confidence", 0.6))

            self._edges.append(
                GraphEdge(
                    source=parent_id,
                    target=child_id,
                    edge_type=EdgeType.DNS_DELEGATION,
                    confidence=confidence,
                )
            )

            # Add IP range nodes if provided.
            ip_ranges = entry.get("ip_ranges") or []
            for ip_range in ip_ranges:
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
                        confidence=confidence,
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
    "EdgeType",
    "GraphEdge",
    "GraphNode",
    "NodeType",
    "OrgGraph",
    "OrgGraphBuilder",
]
