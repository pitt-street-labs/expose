"""Tests for the SOC Threat Package module and API endpoints (issue #115).

Validates:

 1. STIX 2.1 bundle structure (required fields, object types, relationships)
 2. MISP event structure (attributes, tags, threat_level_id)
 3. IoC feed format (required fields, confidence mapping)
 4. Suspicious endpoint detection (positive and negative cases)
 5. API endpoints via httpx AsyncClient + ASGITransport

Uses ``httpx.AsyncClient`` with ``ASGITransport`` against a standalone
FastAPI app that includes only the SOC router (no DB required for
placeholder tests; mock session_factory for real-data tests).
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from expose.api.soc import (
    IoCFeedResponse,
    MispEventResponse,
    StixBundleResponse,
    SuspiciousEndpointEntry,
    SuspiciousEndpointResponse,
    _PLACEHOLDER_ENTITIES,
    router,
)
from expose.modules.soc_package.generator import (
    IoCEntry,
    MISPAttribute,
    MISPEvent,
    MISPTag,
    Severity,
    SocPackageGenerator,
    SuspiciousEndpoint,
)

# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

_TENANT_ID = "00000000-0000-0000-0000-000000000001"
_BASE_URL = f"http://test/v1/tenants/{_TENANT_ID}/soc"


def _make_app() -> FastAPI:
    """Build a minimal FastAPI app with the SOC router mounted."""
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


@pytest.fixture()
def generator() -> SocPackageGenerator:
    """Return a default SocPackageGenerator instance."""
    return SocPackageGenerator()


# ---------------------------------------------------------------------------
# Sample entity data
# ---------------------------------------------------------------------------

_DOMAIN_ENTITY: dict[str, Any] = {
    "entity_type": "domain",
    "canonical_identifier": "test.example.com",
    "properties": {
        "first_observed_at": "2026-01-15T00:00:00.000Z",
        "last_observed_at": "2026-05-11T00:00:00.000Z",
        "attack_techniques": ["T1595", "T1592"],
        "_lead_score": 75,
    },
    "attribution_confidence": 0.85,
}

_IP_ENTITY: dict[str, Any] = {
    "entity_type": "ip",
    "canonical_identifier": "192.0.2.1",
    "properties": {
        "open_ports": [{"port": 22}, {"port": 80}, {"port": 443}],
        "has_waf": False,
        "_lead_score": 60,
    },
    "attribution_confidence": 0.70,
}

_CERT_ENTITY: dict[str, Any] = {
    "entity_type": "certificate",
    "canonical_identifier": "ab:cd:ef:01:23:45",
    "properties": {
        "serial_number": "ABCDEF0123456789",
        "is_self_signed": True,
    },
    "attribution_confidence": 0.50,
}

_RELATIONSHIP: dict[str, Any] = {
    "from_identifier": "test.example.com",
    "to_identifier": "192.0.2.1",
    "edge_type": "resolves-to",
    "confidence": 0.95,
}


# ===========================================================================
# STIX 2.1 Bundle Tests
# ===========================================================================


class TestStixBundle:
    """Validate STIX 2.1 bundle generation."""

    def test_bundle_has_required_fields(self, generator: SocPackageGenerator) -> None:
        bundle = generator.generate_stix_bundle([_DOMAIN_ENTITY])
        assert bundle["type"] == "bundle"
        assert "id" in bundle
        assert bundle["id"].startswith("bundle--")
        assert "objects" in bundle
        assert isinstance(bundle["objects"], list)

    def test_bundle_contains_marking_definition(
        self, generator: SocPackageGenerator
    ) -> None:
        bundle = generator.generate_stix_bundle([_DOMAIN_ENTITY])
        marking_defs = [
            o for o in bundle["objects"] if o["type"] == "marking-definition"
        ]
        assert len(marking_defs) >= 1
        md = marking_defs[0]
        assert md["spec_version"] == "2.1"
        assert "definition_type" in md
        assert md["definition_type"] == "tlp"

    def test_bundle_contains_identity(
        self, generator: SocPackageGenerator
    ) -> None:
        bundle = generator.generate_stix_bundle([_DOMAIN_ENTITY])
        identities = [o for o in bundle["objects"] if o["type"] == "identity"]
        assert len(identities) == 1
        identity = identities[0]
        assert identity["spec_version"] == "2.1"
        assert identity["id"].startswith("identity--")
        assert identity["identity_class"] == "system"
        assert "name" in identity

    def test_domain_mapped_to_infrastructure(
        self, generator: SocPackageGenerator
    ) -> None:
        bundle = generator.generate_stix_bundle([_DOMAIN_ENTITY])
        infra = [
            o for o in bundle["objects"] if o["type"] == "infrastructure"
        ]
        assert len(infra) >= 1
        obj = infra[0]
        assert obj["spec_version"] == "2.1"
        assert obj["id"].startswith("infrastructure--")
        assert obj["infrastructure_types"] == ["domain"]
        assert obj["name"] == "test.example.com"
        assert "confidence" in obj
        assert 0 <= obj["confidence"] <= 100  # noqa: PLR2004

    def test_ip_mapped_to_infrastructure_hosting(
        self, generator: SocPackageGenerator
    ) -> None:
        bundle = generator.generate_stix_bundle([_IP_ENTITY])
        infra = [
            o for o in bundle["objects"] if o["type"] == "infrastructure"
        ]
        assert len(infra) >= 1
        obj = infra[0]
        assert obj["infrastructure_types"] == ["hosting"]
        assert obj["name"] == "192.0.2.1"

    def test_certificate_mapped_to_indicator(
        self, generator: SocPackageGenerator
    ) -> None:
        bundle = generator.generate_stix_bundle([_CERT_ENTITY])
        indicators = [
            o for o in bundle["objects"] if o["type"] == "indicator"
        ]
        assert len(indicators) == 1
        ind = indicators[0]
        assert ind["spec_version"] == "2.1"
        assert ind["id"].startswith("indicator--")
        assert ind["pattern_type"] == "stix"
        assert "x509-certificate:serial_number" in ind["pattern"]
        assert "ABCDEF0123456789" in ind["pattern"]

    def test_relationships_mapped(
        self, generator: SocPackageGenerator
    ) -> None:
        entities = [_DOMAIN_ENTITY, _IP_ENTITY]
        relationships = [_RELATIONSHIP]
        bundle = generator.generate_stix_bundle(entities, relationships)
        rels = [
            o for o in bundle["objects"] if o["type"] == "relationship"
        ]
        assert len(rels) == 1
        rel = rels[0]
        assert rel["spec_version"] == "2.1"
        assert rel["id"].startswith("relationship--")
        assert rel["relationship_type"] == "resolves-to"
        assert rel["source_ref"].startswith("infrastructure--")
        assert rel["target_ref"].startswith("infrastructure--")
        assert 0 <= rel["confidence"] <= 100  # noqa: PLR2004

    def test_sightings_created_for_infrastructure(
        self, generator: SocPackageGenerator
    ) -> None:
        bundle = generator.generate_stix_bundle([_DOMAIN_ENTITY])
        sightings = [o for o in bundle["objects"] if o["type"] == "sighting"]
        assert len(sightings) >= 1
        sighting = sightings[0]
        assert sighting["spec_version"] == "2.1"
        assert sighting["id"].startswith("sighting--")
        assert "first_seen" in sighting
        assert "last_seen" in sighting
        assert "sighting_of_ref" in sighting

    def test_tlp_amber_default(
        self, generator: SocPackageGenerator
    ) -> None:
        bundle = generator.generate_stix_bundle([_DOMAIN_ENTITY])
        marking_defs = [
            o for o in bundle["objects"] if o["type"] == "marking-definition"
        ]
        assert any(
            md["definition"]["tlp"] == "amber" for md in marking_defs
        )

    def test_tlp_configurable(self) -> None:
        gen = SocPackageGenerator(tlp_level="TLP:RED")
        bundle = gen.generate_stix_bundle([_DOMAIN_ENTITY])
        marking_defs = [
            o for o in bundle["objects"] if o["type"] == "marking-definition"
        ]
        assert any(
            md["definition"]["tlp"] == "red" for md in marking_defs
        )

    def test_unknown_tlp_falls_back_to_amber(self) -> None:
        gen = SocPackageGenerator(tlp_level="TLP:NONEXISTENT")
        bundle = gen.generate_stix_bundle([_DOMAIN_ENTITY])
        marking_defs = [
            o for o in bundle["objects"] if o["type"] == "marking-definition"
        ]
        assert any(
            md["definition"]["tlp"] == "amber" for md in marking_defs
        )

    def test_object_marking_refs_present(
        self, generator: SocPackageGenerator
    ) -> None:
        bundle = generator.generate_stix_bundle([_DOMAIN_ENTITY])
        for obj in bundle["objects"]:
            if obj["type"] not in ("marking-definition",):
                assert "object_marking_refs" in obj
                assert len(obj["object_marking_refs"]) >= 1

    def test_confidence_from_attribution(
        self, generator: SocPackageGenerator
    ) -> None:
        entity = {
            "entity_type": "domain",
            "canonical_identifier": "high-conf.example.com",
            "properties": {},
            "attribution_confidence": 0.95,
        }
        bundle = generator.generate_stix_bundle([entity])
        infra = [
            o for o in bundle["objects"] if o["type"] == "infrastructure"
        ]
        assert infra[0]["confidence"] == 95  # noqa: PLR2004

    def test_empty_entities_produces_minimal_bundle(
        self, generator: SocPackageGenerator
    ) -> None:
        bundle = generator.generate_stix_bundle([])
        assert bundle["type"] == "bundle"
        # Should have marking-definition + identity at minimum
        assert len(bundle["objects"]) >= 2  # noqa: PLR2004

    def test_unknown_entity_type_skipped(
        self, generator: SocPackageGenerator
    ) -> None:
        entity = {
            "entity_type": "organization",
            "canonical_identifier": "Acme Corp",
            "properties": {},
            "attribution_confidence": 0.5,
        }
        bundle = generator.generate_stix_bundle([entity])
        # No infrastructure or indicator objects for org type
        infra = [
            o for o in bundle["objects"] if o["type"] == "infrastructure"
        ]
        indicators = [
            o for o in bundle["objects"] if o["type"] == "indicator"
        ]
        assert len(infra) == 0
        assert len(indicators) == 0

    def test_relationship_skipped_when_endpoints_missing(
        self, generator: SocPackageGenerator
    ) -> None:
        # Only one entity, but relationship references two
        bundle = generator.generate_stix_bundle(
            [_DOMAIN_ENTITY], [_RELATIONSHIP]
        )
        rels = [
            o for o in bundle["objects"] if o["type"] == "relationship"
        ]
        assert len(rels) == 0  # target IP entity not in bundle

    def test_multiple_entities_all_represented(
        self, generator: SocPackageGenerator
    ) -> None:
        entities = [_DOMAIN_ENTITY, _IP_ENTITY, _CERT_ENTITY]
        bundle = generator.generate_stix_bundle(entities)
        infra = [
            o for o in bundle["objects"] if o["type"] == "infrastructure"
        ]
        indicators = [
            o for o in bundle["objects"] if o["type"] == "indicator"
        ]
        assert len(infra) == 2  # domain + ip  # noqa: PLR2004
        assert len(indicators) == 1  # certificate


# ===========================================================================
# MISP Event Tests
# ===========================================================================


class TestMispEvent:
    """Validate MISP event generation."""

    def test_event_structure(self, generator: SocPackageGenerator) -> None:
        event = generator.generate_misp_event([_DOMAIN_ENTITY])
        assert "Event" in event
        ev = event["Event"]
        assert "info" in ev
        assert "date" in ev
        assert "threat_level_id" in ev
        assert "Attribute" in ev
        assert "Tag" in ev
        assert "timestamp" in ev

    def test_domain_attribute_type(
        self, generator: SocPackageGenerator
    ) -> None:
        event = generator.generate_misp_event([_DOMAIN_ENTITY])
        attrs = event["Event"]["Attribute"]
        assert len(attrs) >= 1
        assert attrs[0]["type"] == "domain"
        assert attrs[0]["value"] == "test.example.com"

    def test_ip_attribute_type(
        self, generator: SocPackageGenerator
    ) -> None:
        event = generator.generate_misp_event([_IP_ENTITY])
        attrs = event["Event"]["Attribute"]
        assert len(attrs) >= 1
        assert attrs[0]["type"] == "ip-src"
        assert attrs[0]["value"] == "192.0.2.1"

    def test_certificate_attribute_type(
        self, generator: SocPackageGenerator
    ) -> None:
        event = generator.generate_misp_event([_CERT_ENTITY])
        attrs = event["Event"]["Attribute"]
        assert len(attrs) >= 1
        assert attrs[0]["type"] == "x509-fingerprint-sha256"

    def test_attack_technique_tags(
        self, generator: SocPackageGenerator
    ) -> None:
        event = generator.generate_misp_event([_DOMAIN_ENTITY])
        tags = event["Event"]["Tag"]
        tag_names = [t["name"] for t in tags]
        assert "mitre-attack:T1595" in tag_names
        assert "mitre-attack:T1592" in tag_names

    def test_threat_level_high(
        self, generator: SocPackageGenerator
    ) -> None:
        entity = {
            "entity_type": "domain",
            "canonical_identifier": "critical.example.com",
            "properties": {"_lead_score": 90},
            "attribution_confidence": 0.9,
        }
        event = generator.generate_misp_event([entity])
        assert event["Event"]["threat_level_id"] == "1"

    def test_threat_level_medium(
        self, generator: SocPackageGenerator
    ) -> None:
        entity = {
            "entity_type": "domain",
            "canonical_identifier": "medium.example.com",
            "properties": {"_lead_score": 50},
            "attribution_confidence": 0.5,
        }
        event = generator.generate_misp_event([entity])
        assert event["Event"]["threat_level_id"] == "2"

    def test_threat_level_low(
        self, generator: SocPackageGenerator
    ) -> None:
        entity = {
            "entity_type": "domain",
            "canonical_identifier": "low.example.com",
            "properties": {"_lead_score": 10},
            "attribution_confidence": 0.3,
        }
        event = generator.generate_misp_event([entity])
        assert event["Event"]["threat_level_id"] == "3"

    def test_threat_level_undefined(
        self, generator: SocPackageGenerator
    ) -> None:
        entity = {
            "entity_type": "domain",
            "canonical_identifier": "safe.example.com",
            "properties": {"_lead_score": 0},
            "attribution_confidence": 0.1,
        }
        event = generator.generate_misp_event([entity])
        assert event["Event"]["threat_level_id"] == "4"

    def test_custom_scan_summary(
        self, generator: SocPackageGenerator
    ) -> None:
        event = generator.generate_misp_event(
            [_DOMAIN_ENTITY],
            scan_summary="Custom scan of acme.com",
        )
        assert "Custom scan of acme.com" in event["Event"]["info"]

    def test_empty_entities(self, generator: SocPackageGenerator) -> None:
        event = generator.generate_misp_event([])
        assert event["Event"]["Attribute"] == []
        assert event["Event"]["threat_level_id"] == "4"

    def test_duplicate_tags_deduplicated(
        self, generator: SocPackageGenerator
    ) -> None:
        # Two entities with same technique
        entity2 = {
            "entity_type": "ip",
            "canonical_identifier": "10.0.0.1",
            "properties": {"attack_techniques": ["T1595"]},
            "attribution_confidence": 0.5,
        }
        event = generator.generate_misp_event([_DOMAIN_ENTITY, entity2])
        tags = event["Event"]["Tag"]
        tag_names = [t["name"] for t in tags]
        assert tag_names.count("mitre-attack:T1595") == 1


# ===========================================================================
# IoC Feed Tests
# ===========================================================================


class TestIoCFeed:
    """Validate IoC feed generation."""

    def test_feed_entry_has_required_fields(
        self, generator: SocPackageGenerator
    ) -> None:
        feed = generator.generate_ioc_feed([_DOMAIN_ENTITY])
        assert len(feed) >= 1
        entry = feed[0]
        assert "indicator_type" in entry
        assert "indicator_value" in entry
        assert "confidence" in entry
        assert "first_seen" in entry
        assert "last_seen" in entry
        assert "tags" in entry
        assert "description" in entry

    def test_domain_indicator_type(
        self, generator: SocPackageGenerator
    ) -> None:
        feed = generator.generate_ioc_feed([_DOMAIN_ENTITY])
        assert feed[0]["indicator_type"] == "domain"
        assert feed[0]["indicator_value"] == "test.example.com"

    def test_ip_indicator_type(
        self, generator: SocPackageGenerator
    ) -> None:
        feed = generator.generate_ioc_feed([_IP_ENTITY])
        assert feed[0]["indicator_type"] == "ip"
        assert feed[0]["indicator_value"] == "192.0.2.1"

    def test_certificate_indicator_type(
        self, generator: SocPackageGenerator
    ) -> None:
        feed = generator.generate_ioc_feed([_CERT_ENTITY])
        assert feed[0]["indicator_type"] == "hash"

    def test_confidence_mapping(
        self, generator: SocPackageGenerator
    ) -> None:
        # 0.85 -> 85
        feed = generator.generate_ioc_feed([_DOMAIN_ENTITY])
        assert feed[0]["confidence"] == 85  # noqa: PLR2004

    def test_confidence_clamped_to_0_100(
        self, generator: SocPackageGenerator
    ) -> None:
        entity = {
            "entity_type": "domain",
            "canonical_identifier": "over.example.com",
            "properties": {},
            "attribution_confidence": 1.5,  # > 1.0
        }
        feed = generator.generate_ioc_feed([entity])
        assert feed[0]["confidence"] == 100  # noqa: PLR2004

    def test_tags_from_attack_techniques(
        self, generator: SocPackageGenerator
    ) -> None:
        feed = generator.generate_ioc_feed([_DOMAIN_ENTITY])
        assert "T1595" in feed[0]["tags"]
        assert "T1592" in feed[0]["tags"]

    def test_first_seen_last_seen(
        self, generator: SocPackageGenerator
    ) -> None:
        feed = generator.generate_ioc_feed([_DOMAIN_ENTITY])
        entry = feed[0]
        assert "2026-01-15" in entry["first_seen"]
        assert "2026-05-11" in entry["last_seen"]

    def test_empty_entities(self, generator: SocPackageGenerator) -> None:
        feed = generator.generate_ioc_feed([])
        assert feed == []

    def test_unknown_entity_type_skipped(
        self, generator: SocPackageGenerator
    ) -> None:
        entity = {
            "entity_type": "organization",
            "canonical_identifier": "Acme Corp",
            "properties": {},
            "attribution_confidence": 0.5,
        }
        feed = generator.generate_ioc_feed([entity])
        assert len(feed) == 0


# ===========================================================================
# Suspicious Endpoint Detection Tests
# ===========================================================================


class TestSuspiciousEndpointDetection:
    """Validate suspicious endpoint detection."""

    def test_management_ports_detected(
        self, generator: SocPackageGenerator
    ) -> None:
        entity = {
            "entity_type": "ip",
            "canonical_identifier": "10.0.0.1",
            "properties": {
                "open_ports": [{"port": 22}, {"port": 3389}],
                "has_waf": False,
            },
            "attribution_confidence": 0.5,
        }
        endpoints = generator.detect_suspicious_endpoints([entity])
        reasons = [ep.reason for ep in endpoints]
        assert any("22" in r for r in reasons)
        assert any("3389" in r for r in reasons)
        for ep in endpoints:
            assert ep.severity == Severity.HIGH

    def test_management_ports_not_flagged_with_waf(
        self, generator: SocPackageGenerator
    ) -> None:
        entity = {
            "entity_type": "ip",
            "canonical_identifier": "10.0.0.1",
            "properties": {
                "open_ports": [{"port": 22}],
                "has_waf": True,
            },
            "attribution_confidence": 0.5,
        }
        endpoints = generator.detect_suspicious_endpoints([entity])
        mgmt_eps = [
            ep for ep in endpoints
            if "Management port" in ep.reason
        ]
        assert len(mgmt_eps) == 0

    def test_non_management_ports_not_flagged(
        self, generator: SocPackageGenerator
    ) -> None:
        entity = {
            "entity_type": "ip",
            "canonical_identifier": "10.0.0.1",
            "properties": {
                "open_ports": [{"port": 80}, {"port": 443}],
                "has_waf": False,
            },
            "attribution_confidence": 0.5,
        }
        endpoints = generator.detect_suspicious_endpoints([entity])
        mgmt_eps = [
            ep for ep in endpoints
            if "Management port" in ep.reason
        ]
        assert len(mgmt_eps) == 0

    def test_self_signed_cert_on_production_domain(
        self, generator: SocPackageGenerator
    ) -> None:
        entity = {
            "entity_type": "domain",
            "canonical_identifier": "api.example.com",
            "properties": {"is_self_signed": True},
            "attribution_confidence": 0.5,
        }
        endpoints = generator.detect_suspicious_endpoints([entity])
        self_signed = [
            ep for ep in endpoints if "Self-signed" in ep.reason
        ]
        assert len(self_signed) == 1
        assert self_signed[0].severity == Severity.MEDIUM

    def test_self_signed_cert_on_local_domain_not_flagged(
        self, generator: SocPackageGenerator
    ) -> None:
        entity = {
            "entity_type": "domain",
            "canonical_identifier": "dev.local",
            "properties": {"is_self_signed": True},
            "attribution_confidence": 0.5,
        }
        endpoints = generator.detect_suspicious_endpoints([entity])
        self_signed = [
            ep for ep in endpoints if "Self-signed" in ep.reason
        ]
        assert len(self_signed) == 0

    def test_self_signed_cert_on_test_domain_not_flagged(
        self, generator: SocPackageGenerator
    ) -> None:
        entity = {
            "entity_type": "domain",
            "canonical_identifier": "staging.test",
            "properties": {"is_self_signed": True},
            "attribution_confidence": 0.5,
        }
        endpoints = generator.detect_suspicious_endpoints([entity])
        self_signed = [
            ep for ep in endpoints if "Self-signed" in ep.reason
        ]
        assert len(self_signed) == 0

    def test_self_signed_cert_on_ip_not_flagged(
        self, generator: SocPackageGenerator
    ) -> None:
        entity = {
            "entity_type": "ip",
            "canonical_identifier": "10.0.0.1",
            "properties": {"is_self_signed": True},
            "attribution_confidence": 0.5,
        }
        endpoints = generator.detect_suspicious_endpoints([entity])
        self_signed = [
            ep for ep in endpoints if "Self-signed" in ep.reason
        ]
        assert len(self_signed) == 0

    def test_zone_transfer_detected(
        self, generator: SocPackageGenerator
    ) -> None:
        entity = {
            "entity_type": "domain",
            "canonical_identifier": "example.com",
            "properties": {"zone_transfer_allowed": True},
            "attribution_confidence": 0.5,
        }
        endpoints = generator.detect_suspicious_endpoints([entity])
        zt = [ep for ep in endpoints if "zone transfer" in ep.reason.lower()]
        assert len(zt) == 1
        assert zt[0].severity == Severity.HIGH

    def test_zone_transfer_not_flagged_on_ip(
        self, generator: SocPackageGenerator
    ) -> None:
        entity = {
            "entity_type": "ip",
            "canonical_identifier": "10.0.0.1",
            "properties": {"zone_transfer_allowed": True},
            "attribution_confidence": 0.5,
        }
        endpoints = generator.detect_suspicious_endpoints([entity])
        zt = [ep for ep in endpoints if "zone transfer" in ep.reason.lower()]
        assert len(zt) == 0

    def test_debug_headers_detected(
        self, generator: SocPackageGenerator
    ) -> None:
        entity = {
            "entity_type": "domain",
            "canonical_identifier": "app.example.com",
            "properties": {
                "response_headers": {
                    "X-Debug": "true",
                    "X-Powered-By": "Express",
                    "Content-Type": "text/html",  # normal header
                },
            },
            "attribution_confidence": 0.5,
        }
        endpoints = generator.detect_suspicious_endpoints([entity])
        debug = [ep for ep in endpoints if "Debug" in ep.reason or "debug" in ep.reason.lower()]
        assert len(debug) >= 1
        assert debug[0].severity == Severity.MEDIUM

    def test_stack_trace_detected(
        self, generator: SocPackageGenerator
    ) -> None:
        entity = {
            "entity_type": "domain",
            "canonical_identifier": "app.example.com",
            "properties": {"has_stack_trace": True},
            "attribution_confidence": 0.5,
        }
        endpoints = generator.detect_suspicious_endpoints([entity])
        traces = [ep for ep in endpoints if "stack trace" in ep.reason.lower()]
        assert len(traces) == 1
        assert traces[0].severity == Severity.HIGH

    def test_dnsbl_listed_ip_detected(
        self, generator: SocPackageGenerator
    ) -> None:
        entity = {
            "entity_type": "ip",
            "canonical_identifier": "203.0.113.42",
            "properties": {
                "dnsbl_listed": True,
                "dnsbl_lists": ["zen.spamhaus.org"],
            },
            "attribution_confidence": 0.5,
        }
        endpoints = generator.detect_suspicious_endpoints([entity])
        dnsbl = [ep for ep in endpoints if "blacklist" in ep.reason.lower()]
        assert len(dnsbl) == 1
        assert dnsbl[0].severity == Severity.HIGH
        assert "spamhaus" in dnsbl[0].reason.lower()

    def test_dnsbl_not_flagged_on_domain(
        self, generator: SocPackageGenerator
    ) -> None:
        entity = {
            "entity_type": "domain",
            "canonical_identifier": "example.com",
            "properties": {"dnsbl_listed": True},
            "attribution_confidence": 0.5,
        }
        endpoints = generator.detect_suspicious_endpoints([entity])
        dnsbl = [ep for ep in endpoints if "blacklist" in ep.reason.lower()]
        assert len(dnsbl) == 0

    def test_clean_entity_no_findings(
        self, generator: SocPackageGenerator
    ) -> None:
        entity = {
            "entity_type": "domain",
            "canonical_identifier": "clean.example.com",
            "properties": {
                "open_ports": [{"port": 443}],
                "has_waf": True,
            },
            "attribution_confidence": 0.9,
        }
        endpoints = generator.detect_suspicious_endpoints([entity])
        assert len(endpoints) == 0

    def test_multiple_findings_on_one_entity(
        self, generator: SocPackageGenerator
    ) -> None:
        entity = {
            "entity_type": "domain",
            "canonical_identifier": "bad.example.com",
            "properties": {
                "open_ports": [{"port": 22}],
                "has_waf": False,
                "is_self_signed": True,
                "zone_transfer_allowed": True,
                "has_stack_trace": True,
                "response_headers": {"X-Debug": "true"},
            },
            "attribution_confidence": 0.5,
        }
        endpoints = generator.detect_suspicious_endpoints([entity])
        # Should have: mgmt port + self-signed + zone transfer + debug header + stack trace
        assert len(endpoints) >= 5  # noqa: PLR2004

    def test_empty_entities_no_findings(
        self, generator: SocPackageGenerator
    ) -> None:
        endpoints = generator.detect_suspicious_endpoints([])
        assert endpoints == []

    def test_ports_as_integers(
        self, generator: SocPackageGenerator
    ) -> None:
        """Port entries can be plain integers (not dicts)."""
        entity = {
            "entity_type": "ip",
            "canonical_identifier": "10.0.0.1",
            "properties": {
                "open_ports": [22, 80],
                "has_waf": False,
            },
            "attribution_confidence": 0.5,
        }
        endpoints = generator.detect_suspicious_endpoints([entity])
        mgmt = [ep for ep in endpoints if "Management port" in ep.reason]
        assert len(mgmt) == 1


# ===========================================================================
# Dataclass Value Type Tests
# ===========================================================================


class TestValueTypes:
    """Validate dataclass value types are immutable and well-formed."""

    def test_suspicious_endpoint_frozen(self) -> None:
        ep = SuspiciousEndpoint(
            entity_identifier="test.com",
            reason="Test reason",
            severity=Severity.HIGH,
            recommended_action="Fix it",
        )
        with pytest.raises(AttributeError):
            ep.reason = "Changed"  # type: ignore[misc]

    def test_ioc_entry_frozen(self) -> None:
        entry = IoCEntry(
            indicator_type="domain",
            indicator_value="test.com",
            confidence=80,
            first_seen="2026-01-01T00:00:00.000Z",
            last_seen="2026-05-11T00:00:00.000Z",
        )
        assert entry.indicator_type == "domain"
        with pytest.raises(AttributeError):
            entry.confidence = 50  # type: ignore[misc]

    def test_misp_attribute_frozen(self) -> None:
        attr = MISPAttribute(type="domain", value="test.com")
        with pytest.raises(AttributeError):
            attr.value = "changed.com"  # type: ignore[misc]

    def test_misp_tag_frozen(self) -> None:
        tag = MISPTag(name="mitre-attack:T1595")
        assert tag.name == "mitre-attack:T1595"

    def test_misp_event_frozen(self) -> None:
        event = MISPEvent(
            info="Test scan",
            threat_level_id=1,
        )
        with pytest.raises(AttributeError):
            event.info = "Changed"  # type: ignore[misc]


# ===========================================================================
# License Gate Tests
# ===========================================================================


class TestLicenseGate:
    """Validate the module license gate."""

    def test_check_license_returns_true(self) -> None:
        from expose.modules.soc_package import check_license

        assert check_license() is True


# ===========================================================================
# API Endpoint Tests — Placeholder Data
# ===========================================================================


class TestApiEndpointsPlaceholder:
    """Test API endpoints with placeholder data (no DB)."""

    async def test_stix_returns_200(self, client: AsyncClient) -> None:
        resp = await client.get(f"{_BASE_URL}/stix")
        assert resp.status_code == 200

    async def test_stix_response_structure(
        self, client: AsyncClient
    ) -> None:
        resp = await client.get(f"{_BASE_URL}/stix")
        data = resp.json()
        assert data["tenant_id"] == _TENANT_ID
        assert data["is_placeholder"] is True
        assert "generated_at" in data
        assert "bundle" in data
        bundle = data["bundle"]
        assert bundle["type"] == "bundle"
        assert "objects" in bundle
        assert isinstance(bundle["objects"], list)

    async def test_stix_tlp_parameter(
        self, client: AsyncClient
    ) -> None:
        resp = await client.get(f"{_BASE_URL}/stix?tlp=TLP:RED")
        data = resp.json()
        bundle = data["bundle"]
        marking_defs = [
            o for o in bundle["objects"]
            if o["type"] == "marking-definition"
        ]
        assert any(
            md["definition"]["tlp"] == "red" for md in marking_defs
        )

    async def test_misp_returns_200(self, client: AsyncClient) -> None:
        resp = await client.get(f"{_BASE_URL}/misp")
        assert resp.status_code == 200

    async def test_misp_response_structure(
        self, client: AsyncClient
    ) -> None:
        resp = await client.get(f"{_BASE_URL}/misp")
        data = resp.json()
        assert data["tenant_id"] == _TENANT_ID
        assert data["is_placeholder"] is True
        assert "event" in data
        event = data["event"]
        assert "Event" in event
        assert "Attribute" in event["Event"]
        assert "Tag" in event["Event"]

    async def test_ioc_feed_returns_200(
        self, client: AsyncClient
    ) -> None:
        resp = await client.get(f"{_BASE_URL}/ioc-feed")
        assert resp.status_code == 200

    async def test_ioc_feed_response_structure(
        self, client: AsyncClient
    ) -> None:
        resp = await client.get(f"{_BASE_URL}/ioc-feed")
        data = resp.json()
        assert data["tenant_id"] == _TENANT_ID
        assert data["is_placeholder"] is True
        assert "indicators" in data
        assert "total_indicators" in data
        assert isinstance(data["indicators"], list)
        assert data["total_indicators"] == len(data["indicators"])

    async def test_ioc_feed_min_confidence_filter(
        self, client: AsyncClient
    ) -> None:
        resp = await client.get(f"{_BASE_URL}/ioc-feed?min_confidence=90")
        data = resp.json()
        for indicator in data["indicators"]:
            assert indicator["confidence"] >= 90  # noqa: PLR2004

    async def test_suspicious_returns_200(
        self, client: AsyncClient
    ) -> None:
        resp = await client.get(f"{_BASE_URL}/suspicious")
        assert resp.status_code == 200

    async def test_suspicious_response_structure(
        self, client: AsyncClient
    ) -> None:
        resp = await client.get(f"{_BASE_URL}/suspicious")
        data = resp.json()
        assert data["tenant_id"] == _TENANT_ID
        assert data["is_placeholder"] is True
        assert "endpoints" in data
        assert "total_suspicious" in data
        assert isinstance(data["endpoints"], list)
        assert data["total_suspicious"] == len(data["endpoints"])

    async def test_suspicious_has_findings(
        self, client: AsyncClient
    ) -> None:
        """Placeholder data should produce at least some findings."""
        resp = await client.get(f"{_BASE_URL}/suspicious")
        data = resp.json()
        # Placeholder entities have management ports, debug headers, etc.
        assert data["total_suspicious"] > 0

    async def test_suspicious_severity_filter(
        self, client: AsyncClient
    ) -> None:
        resp_all = await client.get(f"{_BASE_URL}/suspicious?min_severity=info")
        resp_high = await client.get(f"{_BASE_URL}/suspicious?min_severity=high")
        all_count = resp_all.json()["total_suspicious"]
        high_count = resp_high.json()["total_suspicious"]
        assert high_count <= all_count

    async def test_suspicious_endpoint_fields(
        self, client: AsyncClient
    ) -> None:
        resp = await client.get(f"{_BASE_URL}/suspicious")
        data = resp.json()
        if data["endpoints"]:
            ep = data["endpoints"][0]
            assert "entity_identifier" in ep
            assert "reason" in ep
            assert "severity" in ep
            assert "recommended_action" in ep


# ===========================================================================
# API Endpoint Tests — Real Data (Mock DB)
# ===========================================================================


def _make_entity_row(
    canonical_identifier: str,
    entity_type: str = "domain",
    properties: dict[str, Any] | None = None,
    attribution_confidence: Decimal = Decimal("0.500"),
) -> MagicMock:
    """Build a mock Entity ORM row with the given properties."""
    entity = MagicMock()
    entity.id = uuid4()
    entity.tenant_id = UUID(_TENANT_ID)
    entity.entity_type = entity_type
    entity.canonical_identifier = canonical_identifier
    entity.properties = properties or {}
    entity.attribution_confidence = attribution_confidence
    entity.last_observed_at = datetime.now(tz=UTC)
    return entity


def _mock_session_factory(entities: list[Any]):
    """Build a mock async session factory that returns entities.

    Returns an async context-manager-compatible callable that mimics
    ``async_sessionmaker().__call__()`` -> session with ``.execute()``.
    """
    mock_result = MagicMock()
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = entities
    mock_result.scalars.return_value = mock_scalars

    # For relationship queries, return empty results.
    mock_empty_result = MagicMock()
    mock_empty_result.all.return_value = []

    call_count = 0

    mock_session = AsyncMock()

    async def _execute_side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # First call: entity query (returns scalars)
            return mock_result
        # Subsequent calls: relationship or entity-id lookups
        return mock_empty_result

    mock_session.execute = AsyncMock(side_effect=_execute_side_effect)

    @asynccontextmanager
    async def factory():
        nonlocal call_count
        # Reset for each context manager entry to handle multiple sessions.
        yield mock_session

    return factory


def _make_app_with_session_factory(entities: list[Any]) -> FastAPI:
    """Build a FastAPI app with a mock session_factory on app.state."""
    app = FastAPI()
    app.include_router(router)
    app.state.session_factory = _mock_session_factory(entities)
    return app


class TestApiEndpointsRealData:
    """Test API endpoints with mock DB data."""

    async def test_stix_real_data(self) -> None:
        entities = [
            _make_entity_row(
                "real.example.com",
                entity_type="domain",
                attribution_confidence=Decimal("0.850"),
            ),
        ]
        app = _make_app_with_session_factory(entities)

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get(f"{_BASE_URL}/stix")

        assert resp.status_code == 200
        data = resp.json()
        assert data["is_placeholder"] is False
        bundle = data["bundle"]
        infra = [
            o for o in bundle["objects"] if o["type"] == "infrastructure"
        ]
        assert len(infra) >= 1
        assert infra[0]["name"] == "real.example.com"

    async def test_misp_real_data(self) -> None:
        entities = [
            _make_entity_row(
                "real.example.com",
                properties={"_lead_score": 80, "attack_techniques": ["T1595"]},
            ),
        ]
        app = _make_app_with_session_factory(entities)

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get(f"{_BASE_URL}/misp")

        assert resp.status_code == 200
        data = resp.json()
        assert data["is_placeholder"] is False
        event = data["event"]["Event"]
        assert len(event["Attribute"]) >= 1
        assert event["threat_level_id"] == "1"

    async def test_ioc_feed_real_data(self) -> None:
        entities = [
            _make_entity_row(
                "real.example.com",
                attribution_confidence=Decimal("0.750"),
            ),
        ]
        app = _make_app_with_session_factory(entities)

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get(f"{_BASE_URL}/ioc-feed")

        assert resp.status_code == 200
        data = resp.json()
        assert data["is_placeholder"] is False
        assert data["total_indicators"] >= 1
        assert data["indicators"][0]["indicator_value"] == "real.example.com"

    async def test_suspicious_real_data(self) -> None:
        entities = [
            _make_entity_row(
                "exposed.example.com",
                properties={
                    "open_ports": [{"port": 22}],
                    "has_waf": False,
                },
            ),
        ]
        app = _make_app_with_session_factory(entities)

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get(f"{_BASE_URL}/suspicious")

        assert resp.status_code == 200
        data = resp.json()
        assert data["is_placeholder"] is False
        assert data["total_suspicious"] >= 1

    async def test_placeholder_fallback_with_no_session_factory(self) -> None:
        """When no session_factory exists (no DB), return placeholders."""
        app = _make_app()

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get(f"{_BASE_URL}/stix")

        data = resp.json()
        assert data["is_placeholder"] is True

    async def test_placeholder_fallback_with_empty_db(self) -> None:
        """When DB has no entities, fall back to placeholders."""
        app = _make_app_with_session_factory([])  # empty
        # Override factory to return None (empty result)
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = []
        mock_result.scalars.return_value = mock_scalars

        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(return_value=mock_result)

        @asynccontextmanager
        async def empty_factory():
            yield mock_session

        app.state.session_factory = empty_factory

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get(f"{_BASE_URL}/stix")

        data = resp.json()
        assert data["is_placeholder"] is True


# ===========================================================================
# Edge Case & Robustness Tests
# ===========================================================================


class TestEdgeCases:
    """Test edge cases and robustness."""

    def test_entity_with_none_properties(
        self, generator: SocPackageGenerator
    ) -> None:
        entity = {
            "entity_type": "domain",
            "canonical_identifier": "null-props.example.com",
            "properties": None,
            "attribution_confidence": 0.5,
        }
        # None of these should raise
        bundle = generator.generate_stix_bundle([entity])
        assert bundle["type"] == "bundle"
        event = generator.generate_misp_event([entity])
        assert "Event" in event
        feed = generator.generate_ioc_feed([entity])
        assert len(feed) >= 1
        endpoints = generator.detect_suspicious_endpoints([entity])
        assert isinstance(endpoints, list)

    def test_entity_with_missing_fields(
        self, generator: SocPackageGenerator
    ) -> None:
        entity: dict[str, Any] = {}
        # Should not raise -- gracefully handles missing data
        bundle = generator.generate_stix_bundle([entity])
        assert bundle["type"] == "bundle"

    def test_invalid_confidence_value(
        self, generator: SocPackageGenerator
    ) -> None:
        entity = {
            "entity_type": "domain",
            "canonical_identifier": "bad-conf.example.com",
            "properties": {},
            "attribution_confidence": "not_a_number",
        }
        bundle = generator.generate_stix_bundle([entity])
        infra = [
            o for o in bundle["objects"] if o["type"] == "infrastructure"
        ]
        assert infra[0]["confidence"] == 0

    def test_subdomain_entity_type(
        self, generator: SocPackageGenerator
    ) -> None:
        entity = {
            "entity_type": "subdomain",
            "canonical_identifier": "sub.test.example.com",
            "properties": {},
            "attribution_confidence": 0.7,
        }
        bundle = generator.generate_stix_bundle([entity])
        infra = [
            o for o in bundle["objects"] if o["type"] == "infrastructure"
        ]
        assert len(infra) == 1
        assert infra[0]["infrastructure_types"] == ["domain"]

    def test_stix_bundle_ids_are_unique(
        self, generator: SocPackageGenerator
    ) -> None:
        entities = [_DOMAIN_ENTITY, _IP_ENTITY, _CERT_ENTITY]
        bundle = generator.generate_stix_bundle(entities)
        ids = [o["id"] for o in bundle["objects"]]
        assert len(ids) == len(set(ids))

    def test_url_entity_type(
        self, generator: SocPackageGenerator
    ) -> None:
        entity = {
            "entity_type": "url",
            "canonical_identifier": "https://example.com/admin",
            "properties": {},
            "attribution_confidence": 0.6,
        }
        bundle = generator.generate_stix_bundle([entity])
        infra = [
            o for o in bundle["objects"] if o["type"] == "infrastructure"
        ]
        assert len(infra) == 1
        assert infra[0]["infrastructure_types"] == ["url"]

        feed = generator.generate_ioc_feed([entity])
        assert feed[0]["indicator_type"] == "url"

    def test_ip_address_entity_type_alias(
        self, generator: SocPackageGenerator
    ) -> None:
        entity = {
            "entity_type": "ip_address",
            "canonical_identifier": "198.51.100.1",
            "properties": {},
            "attribution_confidence": 0.5,
        }
        bundle = generator.generate_stix_bundle([entity])
        infra = [
            o for o in bundle["objects"] if o["type"] == "infrastructure"
        ]
        assert len(infra) == 1
        assert infra[0]["infrastructure_types"] == ["hosting"]

    def test_misp_max_score_across_multiple_entities(
        self, generator: SocPackageGenerator
    ) -> None:
        """threat_level_id should be based on the max score."""
        entities = [
            {
                "entity_type": "domain",
                "canonical_identifier": "a.example.com",
                "properties": {"_lead_score": 10},
                "attribution_confidence": 0.5,
            },
            {
                "entity_type": "domain",
                "canonical_identifier": "b.example.com",
                "properties": {"_lead_score": 80},
                "attribution_confidence": 0.5,
            },
        ]
        event = generator.generate_misp_event(entities)
        # Max score = 80 >= 70 -> threat_level_id = 1 (High)
        assert event["Event"]["threat_level_id"] == "1"
