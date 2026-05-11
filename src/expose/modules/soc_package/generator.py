"""SOC Threat Package generator (EXPOSE commercial module).

Transforms EXPOSE pipeline observations into actionable threat intelligence
packages for SOC teams. Produces STIX 2.1 bundles, MISP events, IoC feeds,
and suspicious-endpoint reports without external library dependencies.

STIX 2.1 conformance: Objects carry ``type``, ``id`` (``type--uuid``),
``created``, ``modified``, ``spec_version: "2.1"``.  No ``stix2`` library
is imported -- conformant JSON dicts are produced directly.

FIPS gate compliance: This module does NOT import ``hashlib``, ``secrets``,
or ``Crypto``. All identifiers are UUID-based.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from expose.sanitization.text import sanitize_field

logger = logging.getLogger(__name__)

# === TLP marking definitions (STIX 2.1) =====================================

_TLP_MARKING_DEFS: dict[str, dict[str, Any]] = {
    "TLP:CLEAR": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:CLEAR",
        "definition": {"tlp": "clear"},
    },
    "TLP:GREEN": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:GREEN",
        "definition": {"tlp": "green"},
    },
    "TLP:AMBER": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:AMBER",
        "definition": {"tlp": "amber"},
    },
    "TLP:AMBER+STRICT": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--826578e1-40a3-4b12-afc0-75e3f8f1fd68",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:AMBER+STRICT",
        "definition": {"tlp": "amber+strict"},
    },
    "TLP:RED": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:RED",
        "definition": {"tlp": "red"},
    },
}


# === Severity enum ===========================================================

class Severity(StrEnum):
    """Severity levels for suspicious endpoint findings."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# === Value types ==============================================================

@dataclass(frozen=True)
class SuspiciousEndpoint:
    """A single suspicious endpoint detected by pattern matching.

    Immutable value type carrying one finding from the suspicious-endpoint
    detector.
    """

    entity_identifier: str
    reason: str
    severity: Severity
    recommended_action: str


@dataclass(frozen=True)
class IoCEntry:
    """A single Indicator of Compromise entry for feed output.

    Immutable value type carrying one IoC record.
    """

    indicator_type: str  # domain, ip, url, hash, certificate
    indicator_value: str
    confidence: int  # 0-100
    first_seen: str  # ISO 8601
    last_seen: str  # ISO 8601
    tags: tuple[str, ...] = field(default_factory=tuple)
    description: str = ""


@dataclass(frozen=True)
class MISPAttribute:
    """A single MISP event attribute."""

    type: str  # domain, ip-src, ip-dst, x509-fingerprint-sha256, etc.
    value: str
    category: str = "Network activity"
    to_ids: bool = True
    comment: str = ""


@dataclass(frozen=True)
class MISPTag:
    """A single MISP event tag."""

    name: str


@dataclass(frozen=True)
class MISPEvent:
    """A MISP event structure."""

    info: str
    threat_level_id: int  # 1=High, 2=Medium, 3=Low, 4=Undefined
    attributes: tuple[MISPAttribute, ...] = field(default_factory=tuple)
    tags: tuple[MISPTag, ...] = field(default_factory=tuple)


# === Entity type to STIX object mapping =======================================

_ENTITY_TYPE_TO_STIX = {
    "domain": ("infrastructure", ["domain"]),
    "subdomain": ("infrastructure", ["domain"]),
    "ip": ("infrastructure", ["hosting"]),
    "ip_address": ("infrastructure", ["hosting"]),
    "cidr": ("infrastructure", ["hosting"]),
    "certificate": ("indicator", None),
    "url": ("infrastructure", ["url"]),
}

# Management ports that signal risk when exposed without WAF.
_MANAGEMENT_PORTS = {22, 23, 3389, 5900, 5985, 5986, 8291}

# Debug/diagnostic HTTP headers that should not appear in production.
_DEBUG_HEADERS = {
    "x-debug",
    "x-debug-token",
    "x-debug-info",
    "x-powered-by",
    "server-timing",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-runtime",
    "x-request-id",
}


def _iso_now() -> str:
    """Return current UTC time in ISO 8601 format."""
    return datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _stix_id(object_type: str) -> str:
    """Generate a STIX-conformant ID: ``type--uuid``."""
    return f"{object_type}--{uuid.uuid4()}"


def _sanitize(value: str) -> str:
    """Sanitize a user-controlled string for output."""
    return sanitize_field(value).value


class SocPackageGenerator:
    """Generate SOC threat intelligence packages from EXPOSE entity data.

    All methods accept plain dicts/lists -- no database dependency. Entity
    dicts are expected to have at minimum:

    - ``entity_type``: str (domain, ip, certificate, etc.)
    - ``canonical_identifier``: str
    - ``properties``: dict (optional; collector-specific metadata)
    - ``attribution_confidence``: float (0.0-1.0)

    Relationship dicts are expected to have:

    - ``from_identifier``: str
    - ``to_identifier``: str
    - ``edge_type``: str
    - ``confidence``: float (0.0-1.0)

    Parameters
    ----------
    tlp_level
        TLP marking to apply to STIX bundles. Default: ``TLP:AMBER``.
    identity_name
        Name for the STIX Identity object representing the scan source.
    """

    def __init__(
        self,
        *,
        tlp_level: str = "TLP:AMBER",
        identity_name: str = "EXPOSE EASI Platform",
    ) -> None:
        self._tlp_level = tlp_level
        self._identity_name = identity_name

    # === STIX 2.1 Bundle =====================================================

    def generate_stix_bundle(
        self,
        entities: list[dict[str, Any]],
        relationships: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Generate a STIX 2.1 Bundle from EXPOSE entities.

        Parameters
        ----------
        entities
            List of entity dicts with ``entity_type``, ``canonical_identifier``,
            ``properties``, ``attribution_confidence``.
        relationships
            Optional list of relationship dicts with ``from_identifier``,
            ``to_identifier``, ``edge_type``, ``confidence``.

        Returns
        -------
        dict
            STIX 2.1 Bundle as a JSON-serializable dict.
        """
        now = _iso_now()
        objects: list[dict[str, Any]] = []

        # TLP marking definition.
        tlp_def = _TLP_MARKING_DEFS.get(self._tlp_level)
        if tlp_def is None:
            logger.warning(
                "Unknown TLP level %r; falling back to TLP:AMBER",
                self._tlp_level,
            )
            tlp_def = _TLP_MARKING_DEFS["TLP:AMBER"]
        marking_ref = tlp_def["id"]
        objects.append(tlp_def)

        # Identity object for the scanner.
        identity_id = _stix_id("identity")
        identity_obj: dict[str, Any] = {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now,
            "modified": now,
            "name": _sanitize(self._identity_name),
            "identity_class": "system",
            "object_marking_refs": [marking_ref],
        }
        objects.append(identity_obj)

        # Map canonical_identifier -> STIX object ID for relationship resolution.
        identifier_to_stix_id: dict[str, str] = {}

        for entity in entities:
            entity_type = entity.get("entity_type", "")
            identifier = entity.get("canonical_identifier", "")
            properties = entity.get("properties", {}) or {}
            confidence_raw = entity.get("attribution_confidence", 0.0)

            # Coerce confidence to int 0-100 for STIX.
            try:
                confidence = max(0, min(100, int(float(confidence_raw) * 100)))
            except (TypeError, ValueError):
                confidence = 0

            stix_mapping = _ENTITY_TYPE_TO_STIX.get(entity_type)

            if stix_mapping is None:
                # Unknown entity type -- skip STIX object creation but log.
                logger.debug(
                    "No STIX mapping for entity_type=%r (%r); skipping",
                    entity_type,
                    identifier,
                )
                continue

            stix_type, infra_types = stix_mapping

            if stix_type == "infrastructure":
                obj_id = _stix_id("infrastructure")
                obj: dict[str, Any] = {
                    "type": "infrastructure",
                    "spec_version": "2.1",
                    "id": obj_id,
                    "created": now,
                    "modified": now,
                    "name": _sanitize(identifier),
                    "infrastructure_types": infra_types or [],
                    "confidence": confidence,
                    "created_by_ref": identity_id,
                    "object_marking_refs": [marking_ref],
                }
                objects.append(obj)
                identifier_to_stix_id[identifier] = obj_id

                # Create a Sighting linking identity to infrastructure.
                sighting_id = _stix_id("sighting")
                first_seen = properties.get("first_observed_at", now)
                last_seen = properties.get("last_observed_at", now)
                sighting: dict[str, Any] = {
                    "type": "sighting",
                    "spec_version": "2.1",
                    "id": sighting_id,
                    "created": now,
                    "modified": now,
                    "first_seen": str(first_seen),
                    "last_seen": str(last_seen),
                    "sighting_of_ref": obj_id,
                    "created_by_ref": identity_id,
                    "object_marking_refs": [marking_ref],
                    "confidence": confidence,
                }
                objects.append(sighting)

            elif stix_type == "indicator":
                # Certificate -> Indicator with x509 pattern.
                obj_id = _stix_id("indicator")
                serial = properties.get(
                    "serial_number",
                    properties.get("fingerprint_sha256", identifier),
                )
                pattern = (
                    f"[x509-certificate:serial_number = "
                    f"'{_sanitize(str(serial))}']"
                )
                obj = {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": obj_id,
                    "created": now,
                    "modified": now,
                    "name": f"Certificate: {_sanitize(identifier)}",
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": now,
                    "confidence": confidence,
                    "created_by_ref": identity_id,
                    "object_marking_refs": [marking_ref],
                }
                objects.append(obj)
                identifier_to_stix_id[identifier] = obj_id

        # Map EXPOSE relationships to STIX relationship objects.
        for rel in relationships or []:
            from_id = rel.get("from_identifier", "")
            to_id = rel.get("to_identifier", "")
            edge_type = rel.get("edge_type", "related-to")
            rel_confidence_raw = rel.get("confidence", 0.0)

            try:
                rel_confidence = max(
                    0, min(100, int(float(rel_confidence_raw) * 100))
                )
            except (TypeError, ValueError):
                rel_confidence = 0

            source_ref = identifier_to_stix_id.get(from_id)
            target_ref = identifier_to_stix_id.get(to_id)

            if source_ref and target_ref:
                rel_obj_id = _stix_id("relationship")
                rel_obj: dict[str, Any] = {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": rel_obj_id,
                    "created": now,
                    "modified": now,
                    "relationship_type": _sanitize(edge_type),
                    "source_ref": source_ref,
                    "target_ref": target_ref,
                    "confidence": rel_confidence,
                    "created_by_ref": identity_id,
                    "object_marking_refs": [marking_ref],
                }
                objects.append(rel_obj)

        bundle: dict[str, Any] = {
            "type": "bundle",
            "id": _stix_id("bundle"),
            "objects": objects,
        }
        return bundle

    # === MISP Event ===========================================================

    def generate_misp_event(
        self,
        entities: list[dict[str, Any]],
        *,
        scan_summary: str = "EXPOSE attack surface scan",
    ) -> dict[str, Any]:
        """Generate a MISP event JSON from EXPOSE entities.

        Parameters
        ----------
        entities
            List of entity dicts.
        scan_summary
            Human-readable summary for the MISP event ``info`` field.

        Returns
        -------
        dict
            MISP event as a JSON-serializable dict.
        """
        now = _iso_now()
        attributes: list[dict[str, Any]] = []
        tags: list[dict[str, str]] = []
        max_score = 0

        seen_tags: set[str] = set()

        for entity in entities:
            entity_type = entity.get("entity_type", "")
            identifier = entity.get("canonical_identifier", "")
            properties = entity.get("properties", {}) or {}

            # Derive MISP attribute type from entity type.
            misp_type = _entity_type_to_misp_type(entity_type)
            if misp_type is None:
                continue

            attr: dict[str, Any] = {
                "type": misp_type,
                "value": _sanitize(identifier),
                "category": "Network activity",
                "to_ids": True,
                "comment": _sanitize(
                    properties.get("_justification", f"EXPOSE {entity_type}")
                ),
            }
            attributes.append(attr)

            # Track max lead score for threat_level_id.
            lead_score = properties.get("_lead_score", 0)
            try:
                lead_score = int(lead_score)
            except (TypeError, ValueError):
                lead_score = 0
            if lead_score > max_score:
                max_score = lead_score

            # Collect ATT&CK technique tags from collectors.
            attack_techniques = properties.get("attack_techniques", [])
            if isinstance(attack_techniques, list):
                for tech in attack_techniques:
                    tech_str = str(tech)
                    if tech_str not in seen_tags:
                        tags.append({"name": f"mitre-attack:{_sanitize(tech_str)}"})
                        seen_tags.add(tech_str)

        # Map max lead score to MISP threat_level_id.
        # 1=High (>=70), 2=Medium (>=40), 3=Low (>=1), 4=Undefined (0)
        if max_score >= 70:  # noqa: PLR2004
            threat_level_id = 1
        elif max_score >= 40:  # noqa: PLR2004
            threat_level_id = 2
        elif max_score >= 1:
            threat_level_id = 3
        else:
            threat_level_id = 4

        event: dict[str, Any] = {
            "Event": {
                "info": _sanitize(scan_summary),
                "date": datetime.now(tz=UTC).strftime("%Y-%m-%d"),
                "threat_level_id": str(threat_level_id),
                "analysis": "2",  # "2" = completed
                "distribution": "0",  # "0" = your organization only
                "Attribute": attributes,
                "Tag": tags,
                "timestamp": now,
            }
        }
        return event

    # === IoC Feed =============================================================

    def generate_ioc_feed(
        self,
        entities: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Generate a simple IoC feed from EXPOSE entities.

        Parameters
        ----------
        entities
            List of entity dicts.

        Returns
        -------
        list
            JSON-serializable list of IoC entry dicts.
        """
        feed: list[dict[str, Any]] = []
        now = _iso_now()

        for entity in entities:
            entity_type = entity.get("entity_type", "")
            identifier = entity.get("canonical_identifier", "")
            properties = entity.get("properties", {}) or {}
            confidence_raw = entity.get("attribution_confidence", 0.0)

            # Map entity type to IoC indicator type.
            ioc_type = _entity_type_to_ioc_type(entity_type)
            if ioc_type is None:
                continue

            # Confidence: 0.0-1.0 -> 0-100
            try:
                confidence = max(0, min(100, int(float(confidence_raw) * 100)))
            except (TypeError, ValueError):
                confidence = 0

            first_seen = str(properties.get("first_observed_at", now))
            last_seen = str(properties.get("last_observed_at", now))

            # Collect ATT&CK tags.
            attack_techniques = properties.get("attack_techniques", [])
            tags: list[str] = []
            if isinstance(attack_techniques, list):
                for tech in attack_techniques:
                    tags.append(str(tech))

            description = _sanitize(
                properties.get(
                    "_justification",
                    f"EXPOSE observed {entity_type}: {identifier}",
                )
            )

            entry: dict[str, Any] = {
                "indicator_type": ioc_type,
                "indicator_value": _sanitize(identifier),
                "confidence": confidence,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "tags": tags,
                "description": description,
            }
            feed.append(entry)

        return feed

    # === Suspicious Endpoint Detection ========================================

    def detect_suspicious_endpoints(
        self,
        entities: list[dict[str, Any]],
    ) -> list[SuspiciousEndpoint]:
        """Identify entities matching suspicious patterns.

        Checks for:
        - Open management ports (SSH, RDP, VNC, etc.) without WAF
        - Self-signed certificates on production-like domains
        - DNS zones allowing zone transfer
        - HTTP responses with debug headers or stack traces
        - DNSBL-listed IPs

        Parameters
        ----------
        entities
            List of entity dicts with properties containing observation data.

        Returns
        -------
        list
            List of ``SuspiciousEndpoint`` dataclasses.
        """
        results: list[SuspiciousEndpoint] = []

        for entity in entities:
            identifier = entity.get("canonical_identifier", "")
            entity_type = entity.get("entity_type", "")
            properties = entity.get("properties", {}) or {}

            results.extend(
                self._check_management_ports(identifier, properties)
            )
            results.extend(
                self._check_self_signed_certs(
                    identifier, entity_type, properties
                )
            )
            results.extend(
                self._check_zone_transfer(identifier, entity_type, properties)
            )
            results.extend(
                self._check_debug_headers(identifier, properties)
            )
            results.extend(
                self._check_dnsbl(identifier, entity_type, properties)
            )

        return results

    # === Private detection helpers ============================================

    @staticmethod
    def _check_management_ports(
        identifier: str,
        properties: dict[str, Any],
    ) -> list[SuspiciousEndpoint]:
        """Flag open management ports without WAF protection."""
        results: list[SuspiciousEndpoint] = []
        open_ports = properties.get("open_ports", [])
        has_waf = properties.get("has_waf", False)

        if has_waf:
            return results

        if isinstance(open_ports, list):
            for port_entry in open_ports:
                port_num: int | None = None
                if isinstance(port_entry, dict):
                    port_num = port_entry.get("port")
                elif isinstance(port_entry, int):
                    port_num = port_entry

                if port_num is not None and port_num in _MANAGEMENT_PORTS:
                    results.append(SuspiciousEndpoint(
                        entity_identifier=identifier,
                        reason=(
                            f"Management port {port_num} is open without "
                            f"WAF protection"
                        ),
                        severity=Severity.HIGH,
                        recommended_action=(
                            f"Restrict access to port {port_num} via "
                            f"firewall rules or deploy a WAF. Consider "
                            f"VPN-only access for management interfaces."
                        ),
                    ))

        return results

    @staticmethod
    def _check_self_signed_certs(
        identifier: str,
        entity_type: str,
        properties: dict[str, Any],
    ) -> list[SuspiciousEndpoint]:
        """Flag self-signed certificates on production-like domains."""
        results: list[SuspiciousEndpoint] = []
        is_self_signed = properties.get("is_self_signed", False)

        if not is_self_signed:
            return results

        # Only flag on domain/subdomain/certificate entities -- not IPs
        # where self-signed is more common and expected.
        if entity_type in ("domain", "subdomain", "certificate"):
            # Check if identifier looks like a production domain
            # (not localhost, not .local, not .test, not .internal).
            non_prod_suffixes = (
                "localhost",
                ".local",
                ".test",
                ".internal",
                ".example",
                ".invalid",
                ".lan",
            )
            id_lower = identifier.lower()
            is_non_prod = any(
                id_lower.endswith(suffix) or id_lower == suffix.lstrip(".")
                for suffix in non_prod_suffixes
            )

            if not is_non_prod:
                results.append(SuspiciousEndpoint(
                    entity_identifier=identifier,
                    reason="Self-signed certificate on production-like domain",
                    severity=Severity.MEDIUM,
                    recommended_action=(
                        "Replace self-signed certificate with a CA-issued "
                        "certificate. Self-signed certificates enable "
                        "man-in-the-middle attacks and erode user trust."
                    ),
                ))

        return results

    @staticmethod
    def _check_zone_transfer(
        identifier: str,
        entity_type: str,
        properties: dict[str, Any],
    ) -> list[SuspiciousEndpoint]:
        """Flag DNS zones that allow zone transfer (AXFR)."""
        results: list[SuspiciousEndpoint] = []
        allows_transfer = properties.get("zone_transfer_allowed", False)

        if allows_transfer and entity_type in ("domain", "subdomain"):
            results.append(SuspiciousEndpoint(
                entity_identifier=identifier,
                reason="DNS zone allows zone transfer (AXFR)",
                severity=Severity.HIGH,
                recommended_action=(
                    "Disable zone transfers or restrict to authorized "
                    "secondary nameservers only. Zone transfers expose "
                    "the complete DNS zone contents to attackers."
                ),
            ))

        return results

    @staticmethod
    def _check_debug_headers(
        identifier: str,
        properties: dict[str, Any],
    ) -> list[SuspiciousEndpoint]:
        """Flag HTTP responses with debug headers or stack traces."""
        results: list[SuspiciousEndpoint] = []
        response_headers = properties.get("response_headers", {})
        has_stack_trace = properties.get("has_stack_trace", False)

        if isinstance(response_headers, dict):
            found_debug = []
            for header_name in response_headers:
                if header_name.lower() in _DEBUG_HEADERS:
                    found_debug.append(header_name)

            if found_debug:
                results.append(SuspiciousEndpoint(
                    entity_identifier=identifier,
                    reason=(
                        f"Debug/diagnostic HTTP headers present: "
                        f"{', '.join(sorted(found_debug))}"
                    ),
                    severity=Severity.MEDIUM,
                    recommended_action=(
                        "Remove debug and diagnostic headers from "
                        "production HTTP responses. These headers leak "
                        "technology stack details to attackers."
                    ),
                ))

        if has_stack_trace:
            results.append(SuspiciousEndpoint(
                entity_identifier=identifier,
                reason="HTTP response contains stack trace",
                severity=Severity.HIGH,
                recommended_action=(
                    "Disable verbose error pages in production. Stack "
                    "traces reveal internal code paths, library versions, "
                    "and potential injection points."
                ),
            ))

        return results

    @staticmethod
    def _check_dnsbl(
        identifier: str,
        entity_type: str,
        properties: dict[str, Any],
    ) -> list[SuspiciousEndpoint]:
        """Flag IPs that appear on DNS blacklists."""
        results: list[SuspiciousEndpoint] = []
        dnsbl_listed = properties.get("dnsbl_listed", False)
        dnsbl_lists = properties.get("dnsbl_lists", [])

        if dnsbl_listed and entity_type in ("ip", "ip_address"):
            list_names = ", ".join(str(bl) for bl in dnsbl_lists) if dnsbl_lists else "unknown"
            results.append(SuspiciousEndpoint(
                entity_identifier=identifier,
                reason=f"IP is listed on DNS blacklists: {list_names}",
                severity=Severity.HIGH,
                recommended_action=(
                    "Investigate why this IP is blacklisted. It may be "
                    "compromised, sending spam, or hosting malicious "
                    "content. Request delisting after remediation."
                ),
            ))

        return results


# === Helper functions =========================================================


def _entity_type_to_misp_type(entity_type: str) -> str | None:
    """Map an EXPOSE entity type to a MISP attribute type.

    Returns None for entity types that have no natural MISP mapping.
    """
    mapping: dict[str, str] = {
        "domain": "domain",
        "subdomain": "domain",
        "ip": "ip-src",
        "ip_address": "ip-src",
        "cidr": "ip-src",
        "certificate": "x509-fingerprint-sha256",
        "url": "url",
    }
    return mapping.get(entity_type)


def _entity_type_to_ioc_type(entity_type: str) -> str | None:
    """Map an EXPOSE entity type to an IoC indicator type.

    Returns None for entity types not suitable for IoC feeds.
    """
    mapping: dict[str, str] = {
        "domain": "domain",
        "subdomain": "domain",
        "ip": "ip",
        "ip_address": "ip",
        "cidr": "ip",
        "certificate": "hash",
        "url": "url",
    }
    return mapping.get(entity_type)


__all__ = [
    "IoCEntry",
    "MISPAttribute",
    "MISPEvent",
    "MISPTag",
    "Severity",
    "SocPackageGenerator",
    "SuspiciousEndpoint",
]
