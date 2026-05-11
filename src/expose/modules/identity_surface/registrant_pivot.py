"""Registrant pivot: cluster domains by shared WHOIS/RDAP registrant identity.

Correlates registrant data across domains to find assets registered by the
same entity despite name variations, different registrars, or partial
redaction. Uses ``difflib.SequenceMatcher`` for fuzzy string matching
(stdlib only -- no external dependencies).

Ethics gate: operations are refused unless ``per_tenant_authorization=True``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from enum import StrEnum
from typing import Any

from pydantic import BaseModel

# Common corporate suffixes stripped before fuzzy comparison so that
# "Acme Corp" matches "ACME Corporation" even when SequenceMatcher
# would rate the raw strings below threshold. The list is intentionally
# conservative -- only unambiguous organisational suffixes.
_CORP_SUFFIX_RE = re.compile(
    r"\b("
    r"corporation|corp\.?|incorporated|inc\.?|"
    r"limited|ltd\.?|llc\.?|llp\.?|"
    r"gmbh|ag|sa|srl|pty\.?\s*ltd\.?|"
    r"plc|co\.?|company"
    r")\s*$",
    re.IGNORECASE,
)


class WhoisEntity(BaseModel):
    """Typed model for WHOIS/RDAP entity input data.

    Replaces ``dict[str, Any]`` inputs to ``RegistrantPivot.pivot()``
    for type safety. Legacy dict inputs are still accepted via
    ``model_validate()`` for backward compatibility.
    """

    domain: str
    registrant_org: str | None = None
    registrant_email: str | None = None
    registrant_city: str | None = None
    registrant_country: str | None = None
    name_servers: list[str] = []


class PivotDimension(StrEnum):
    """Dimension used to group domains in a registrant pivot."""

    ORG_NAME = "org_name"
    EMAIL_DOMAIN = "email_domain"
    ADDRESS = "address"
    NAME_SERVER = "name_server"


@dataclass(frozen=True)
class ClusterMember:
    """A single domain within a pivot cluster."""

    domain: str
    registrant_org: str | None = None
    registrant_email: str | None = None
    registrant_city: str | None = None
    registrant_country: str | None = None
    name_servers: tuple[str, ...] = ()


@dataclass(frozen=True)
class PivotCluster:
    """A group of related domains sharing a registrant attribute.

    ``dimension`` indicates which pivot axis created this cluster.
    ``confidence`` is in [0.0, 1.0] -- higher means stronger evidence
    that the members share a single registrant entity.
    ``key`` is the canonical value that anchored the cluster (e.g., the
    normalized org name, the email domain, or the city+country string).
    """

    dimension: PivotDimension
    key: str
    confidence: float
    members: tuple[ClusterMember, ...]


@dataclass(frozen=True)
class PivotResult:
    """Output of a registrant pivot operation.

    ``clusters`` contains all groups found across every pivot dimension.
    A domain may appear in multiple clusters (e.g., matched by both org
    name and email domain).
    """

    clusters: tuple[PivotCluster, ...]


class RegistrantPivotError(Exception):
    """Raised when a registrant pivot operation fails."""


class AuthorizationError(RegistrantPivotError):
    """Raised when per-tenant authorization has not been granted."""


def _coerce_whois_entities(
    entities: list[WhoisEntity | dict[str, Any]],
) -> list[WhoisEntity]:
    """Coerce a mixed list of ``WhoisEntity`` models and dicts.

    Dict entries are validated via ``WhoisEntity.model_validate()``.
    Dicts missing the required ``domain`` key are silently skipped
    (matching the previous behavior of ``_build_members``).
    """
    result: list[WhoisEntity] = []
    for entry in entities:
        if isinstance(entry, WhoisEntity):
            result.append(entry)
        elif isinstance(entry, dict):
            if "domain" not in entry or not entry["domain"]:
                continue
            result.append(WhoisEntity.model_validate(entry))
        else:
            raise TypeError(
                f"Expected WhoisEntity or dict, got {type(entry).__name__}"
            )
    return result


class RegistrantPivot:
    """Correlate WHOIS/RDAP registrant data across domains.

    Parameters
    ----------
    per_tenant_authorization:
        Must be ``True`` to enable operations. When ``False`` (the default),
        all pivot methods raise ``AuthorizationError``. This is the ethics
        gate required by EXPOSE Identity Surface policy.
    fuzzy_threshold:
        Minimum ``SequenceMatcher.ratio()`` for two org names to be
        considered a fuzzy match. Default is 0.85.
    """

    def __init__(
        self,
        *,
        per_tenant_authorization: bool = False,
        fuzzy_threshold: float = 0.85,
    ) -> None:
        self._authorized = per_tenant_authorization
        self._fuzzy_threshold = fuzzy_threshold

    def _require_auth(self) -> None:
        """Raise ``AuthorizationError`` if not authorized."""
        if not self._authorized:
            raise AuthorizationError(
                "Identity Surface operations require per_tenant_authorization=True. "
                "See IDENTITY_SURFACE_ETHICS.md for consent and scope requirements."
            )

    def pivot(self, entities: list[WhoisEntity | dict[str, Any]]) -> PivotResult:
        """Run the full registrant pivot across all dimensions.

        Parameters
        ----------
        entities:
            List of ``WhoisEntity`` models (preferred) or dicts with WHOIS
            properties (backward-compatible). Dict inputs are coerced to
            ``WhoisEntity`` via ``model_validate()``. Expected keys
            (all optional except ``domain``): ``domain``,
            ``registrant_org``, ``registrant_email``,
            ``registrant_city``, ``registrant_country``,
            ``name_servers`` (list of strings).

        Returns
        -------
        PivotResult
            Clusters of related domains grouped by each pivot dimension.

        Raises
        ------
        AuthorizationError
            If ``per_tenant_authorization`` was not set to ``True``.
        """
        self._require_auth()

        validated = _coerce_whois_entities(entities)
        members = self._build_members(validated)
        clusters: list[PivotCluster] = []

        clusters.extend(self._pivot_by_org_name(members))
        clusters.extend(self._pivot_by_email_domain(members))
        clusters.extend(self._pivot_by_address(members))
        clusters.extend(self._pivot_by_name_server(members))

        return PivotResult(clusters=tuple(clusters))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_members(entities: list[WhoisEntity]) -> list[ClusterMember]:
        """Convert ``WhoisEntity`` instances to ``ClusterMember`` instances."""
        members: list[ClusterMember] = []
        for entity in entities:
            if not entity.domain:
                continue
            members.append(
                ClusterMember(
                    domain=entity.domain.lower().strip(),
                    registrant_org=entity.registrant_org,
                    registrant_email=entity.registrant_email,
                    registrant_city=entity.registrant_city,
                    registrant_country=entity.registrant_country,
                    name_servers=tuple(
                        str(ns).lower().strip() for ns in entity.name_servers
                    ),
                )
            )
        return members

    @staticmethod
    def _normalize_org_name(name: str) -> str:
        """Normalize an org name for fuzzy comparison.

        Strips common corporate suffixes (Corp, Inc, LLC, etc.),
        collapses whitespace, and lowercases. This dramatically
        improves SequenceMatcher accuracy for registrant names that
        differ only in suffix style (e.g., "Acme Corp" vs
        "ACME Corporation").
        """
        normalized = name.lower().strip()
        # Strip trailing punctuation before suffix removal.
        normalized = normalized.rstrip(".,;")
        # Remove corporate suffixes.
        normalized = _CORP_SUFFIX_RE.sub("", normalized).strip()
        # Collapse internal whitespace.
        normalized = re.sub(r"\s+", " ", normalized)
        return normalized

    def _org_fuzzy_match(self, a: str, b: str) -> float:
        """Compare two org names with suffix normalization.

        First compares normalized forms (corporate suffixes stripped).
        Falls back to raw comparison if normalized forms are empty
        (edge case: org name is only a suffix like "LLC").
        Returns the maximum of normalized and raw ratios so that
        exact raw matches still score 1.0.
        """
        norm_a = self._normalize_org_name(a)
        norm_b = self._normalize_org_name(b)

        # If normalization ate the entire name, fall back to raw.
        if not norm_a or not norm_b:
            return SequenceMatcher(None, a.lower(), b.lower()).ratio()

        norm_ratio = SequenceMatcher(None, norm_a, norm_b).ratio()
        raw_ratio = SequenceMatcher(None, a.lower(), b.lower()).ratio()
        return max(norm_ratio, raw_ratio)

    def _pivot_by_org_name(
        self, members: list[ClusterMember]
    ) -> list[PivotCluster]:
        """Group by fuzzy-matched registrant organization name."""
        # Collect members that have an org name.
        with_org = [m for m in members if m.registrant_org]
        if not with_org:
            return []

        # Greedy clustering: iterate members, assign to existing cluster
        # if fuzzy match exceeds threshold, otherwise start a new cluster.
        cluster_groups: list[list[tuple[ClusterMember, float]]] = []
        cluster_keys: list[str] = []

        for member in with_org:
            org_lower = member.registrant_org.lower().strip()  # type: ignore[union-attr]
            placed = False

            for idx, key in enumerate(cluster_keys):
                ratio = self._org_fuzzy_match(key, org_lower)
                if ratio >= self._fuzzy_threshold:
                    cluster_groups[idx].append((member, ratio))
                    placed = True
                    break

            if not placed:
                cluster_keys.append(org_lower)
                cluster_groups.append([(member, 1.0)])

        clusters: list[PivotCluster] = []
        for key, group in zip(cluster_keys, cluster_groups):
            if len(group) < 2:
                continue
            avg_confidence = sum(r for _, r in group) / len(group)
            clusters.append(
                PivotCluster(
                    dimension=PivotDimension.ORG_NAME,
                    key=key,
                    confidence=min(avg_confidence, 1.0),
                    members=tuple(m for m, _ in group),
                )
            )

        return clusters

    def _pivot_by_email_domain(
        self, members: list[ClusterMember]
    ) -> list[PivotCluster]:
        """Group by registrant email domain (part after ``@``)."""
        domain_map: dict[str, list[ClusterMember]] = {}

        for member in members:
            email = member.registrant_email
            if not email or "@" not in email:
                continue
            email_domain = email.split("@", 1)[1].lower().strip()
            # Skip common free-email providers -- they do not indicate
            # shared ownership.
            if email_domain in {
                "gmail.com",
                "yahoo.com",
                "hotmail.com",
                "outlook.com",
                "protonmail.com",
                "mail.com",
                "aol.com",
                "icloud.com",
            }:
                continue
            domain_map.setdefault(email_domain, []).append(member)

        return [
            PivotCluster(
                dimension=PivotDimension.EMAIL_DOMAIN,
                key=domain,
                confidence=0.80,
                members=tuple(group),
            )
            for domain, group in domain_map.items()
            if len(group) >= 2
        ]

    @staticmethod
    def _pivot_by_address(
        members: list[ClusterMember],
    ) -> list[PivotCluster]:
        """Group by registrant city + country."""
        addr_map: dict[str, list[ClusterMember]] = {}

        for member in members:
            city = member.registrant_city
            country = member.registrant_country
            if not city or not country:
                continue
            key = f"{city.lower().strip()}, {country.lower().strip()}"
            addr_map.setdefault(key, []).append(member)

        return [
            PivotCluster(
                dimension=PivotDimension.ADDRESS,
                key=addr,
                confidence=0.60,
                members=tuple(group),
            )
            for addr, group in addr_map.items()
            if len(group) >= 2
        ]

    @staticmethod
    def _pivot_by_name_server(
        members: list[ClusterMember],
    ) -> list[PivotCluster]:
        """Group by shared name server patterns.

        Two members are grouped if they share at least one name server.
        A greedy approach groups members by the name server they share.
        """
        ns_map: dict[str, list[ClusterMember]] = {}

        for member in members:
            for ns in member.name_servers:
                ns_map.setdefault(ns, []).append(member)

        # Deduplicate: a member may share multiple name servers within
        # one cluster.  Build per-NS clusters, then deduplicate by member set.
        seen_member_sets: set[frozenset[str]] = set()
        clusters: list[PivotCluster] = []

        for ns, group in ns_map.items():
            if len(group) < 2:
                continue
            member_key = frozenset(m.domain for m in group)
            if member_key in seen_member_sets:
                continue
            seen_member_sets.add(member_key)
            clusters.append(
                PivotCluster(
                    dimension=PivotDimension.NAME_SERVER,
                    key=ns,
                    confidence=0.50,
                    members=tuple(group),
                )
            )

        return clusters


__all__ = [
    "AuthorizationError",
    "ClusterMember",
    "PivotCluster",
    "PivotDimension",
    "PivotResult",
    "RegistrantPivot",
    "RegistrantPivotError",
    "WhoisEntity",
]
