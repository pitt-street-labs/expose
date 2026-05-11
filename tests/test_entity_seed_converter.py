"""Tests for the entity-to-seed converter (pipeline feedback loop).

Covers:
- Domain entities -> DOMAIN seeds
- Subdomain entities -> DOMAIN seeds
- IP entities -> IP seeds
- CIDR entities -> CIDR seeds
- Organization entities -> ORGANIZATION seeds
- Cloud resource entities -> skipped
- Certificate entities -> skipped
- Deduplication via already_scanned set
- Within-batch deduplication
- RDAP org extraction from properties (both key variants)
- Empty / edge-case input handling
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from uuid import uuid4

import pytest

from expose.collectors.base import SeedType
from expose.db.models import Entity
from expose.pipeline.entity_seed_converter import (
    entities_to_seeds,
    extract_org_seeds_from_properties,
)

# ---------------------------------------------------------------------------
# Helper — minimal Entity factory
# ---------------------------------------------------------------------------

_TENANT_ID = uuid4()


def _make_entity(
    entity_type: str,
    canonical_identifier: str,
    properties: dict | None = None,
) -> Entity:
    """Build an Entity with only the fields the converter inspects."""
    now = datetime.now(timezone.utc)
    return Entity(
        id=uuid4(),
        tenant_id=_TENANT_ID,
        entity_type=entity_type,
        canonical_identifier=canonical_identifier,
        properties=properties or {},
        attribution_status="confirmed",
        attribution_confidence=Decimal("0.900"),
        first_observed_at=now,
        last_observed_at=now,
    )


# ===================================================================
# entities_to_seeds
# ===================================================================


class TestEntitiesToSeeds:
    """Core conversion from Entity rows to Seed objects."""

    def test_domain_entity_produces_domain_seed(self) -> None:
        entity = _make_entity("domain", "example.com")
        seeds = entities_to_seeds([entity], set())
        assert len(seeds) == 1
        assert seeds[0].seed_type == SeedType.DOMAIN
        assert seeds[0].value == "example.com"

    def test_subdomain_entity_produces_domain_seed(self) -> None:
        entity = _make_entity("subdomain", "api.example.com")
        seeds = entities_to_seeds([entity], set())
        assert len(seeds) == 1
        assert seeds[0].seed_type == SeedType.DOMAIN
        assert seeds[0].value == "api.example.com"

    def test_ip_entity_produces_ip_seed(self) -> None:
        entity = _make_entity("ip", "192.0.2.1")
        seeds = entities_to_seeds([entity], set())
        assert len(seeds) == 1
        assert seeds[0].seed_type == SeedType.IP
        assert seeds[0].value == "192.0.2.1"

    def test_ip_address_entity_produces_ip_seed(self) -> None:
        entity = _make_entity("ip_address", "198.51.100.5")
        seeds = entities_to_seeds([entity], set())
        assert len(seeds) == 1
        assert seeds[0].seed_type == SeedType.IP
        assert seeds[0].value == "198.51.100.5"

    def test_cidr_entity_produces_cidr_seed(self) -> None:
        entity = _make_entity("cidr", "10.0.0.0/24")
        seeds = entities_to_seeds([entity], set())
        assert len(seeds) == 1
        assert seeds[0].seed_type == SeedType.CIDR
        assert seeds[0].value == "10.0.0.0/24"

    def test_organization_entity_produces_organization_seed(self) -> None:
        entity = _make_entity("organization", "Acme Corp")
        seeds = entities_to_seeds([entity], set())
        assert len(seeds) == 1
        assert seeds[0].seed_type == SeedType.ORGANIZATION
        assert seeds[0].value == "Acme Corp"

    def test_cloud_resource_entity_is_skipped(self) -> None:
        entity = _make_entity("cloud_resource_id", "arn:aws:s3:::my-bucket")
        seeds = entities_to_seeds([entity], set())
        assert seeds == []

    def test_certificate_entity_is_skipped(self) -> None:
        entity = _make_entity("certificate", "sha256:abc123")
        seeds = entities_to_seeds([entity], set())
        assert seeds == []

    def test_unknown_entity_type_is_skipped(self) -> None:
        entity = _make_entity("unknown_type", "some-value")
        seeds = entities_to_seeds([entity], set())
        assert seeds == []

    def test_mixed_entity_types(self) -> None:
        entities = [
            _make_entity("domain", "example.com"),
            _make_entity("ip", "192.0.2.1"),
            _make_entity("organization", "Acme Corp"),
            _make_entity("certificate", "sha256:abc"),
            _make_entity("cloud_resource_id", "arn:aws:s3:::bucket"),
            _make_entity("subdomain", "mail.example.com"),
            _make_entity("cidr", "10.0.0.0/8"),
        ]
        seeds = entities_to_seeds(entities, set())
        assert len(seeds) == 5
        seed_types = [(s.seed_type, s.value) for s in seeds]
        assert (SeedType.DOMAIN, "example.com") in seed_types
        assert (SeedType.IP, "192.0.2.1") in seed_types
        assert (SeedType.ORGANIZATION, "Acme Corp") in seed_types
        assert (SeedType.DOMAIN, "mail.example.com") in seed_types
        assert (SeedType.CIDR, "10.0.0.0/8") in seed_types


class TestEntitiesToSeedsDeduplication:
    """Deduplication via already_scanned and within-batch."""

    def test_already_scanned_domain_is_excluded(self) -> None:
        entity = _make_entity("domain", "example.com")
        already = {("domain", "example.com")}
        seeds = entities_to_seeds([entity], already)
        assert seeds == []

    def test_already_scanned_ip_is_excluded(self) -> None:
        entity = _make_entity("ip", "192.0.2.1")
        already = {("ip", "192.0.2.1")}
        seeds = entities_to_seeds([entity], already)
        assert seeds == []

    def test_already_scanned_org_is_excluded(self) -> None:
        entity = _make_entity("organization", "Acme Corp")
        already = {("organization", "Acme Corp")}
        seeds = entities_to_seeds([entity], already)
        assert seeds == []

    def test_partial_already_scanned(self) -> None:
        """Only the scanned one is excluded; the other passes through."""
        entities = [
            _make_entity("domain", "example.com"),
            _make_entity("domain", "other.com"),
        ]
        already = {("domain", "example.com")}
        seeds = entities_to_seeds(entities, already)
        assert len(seeds) == 1
        assert seeds[0].value == "other.com"

    def test_within_batch_deduplication(self) -> None:
        """Two entities with same type+value produce only one seed."""
        entities = [
            _make_entity("domain", "example.com"),
            _make_entity("domain", "example.com"),
        ]
        seeds = entities_to_seeds(entities, set())
        assert len(seeds) == 1

    def test_same_value_different_types_not_deduplicated(self) -> None:
        """'10.0.0.0/24' as cidr and '10.0.0.0/24' as domain are distinct."""
        entities = [
            _make_entity("cidr", "10.0.0.0/24"),
            _make_entity("domain", "10.0.0.0/24"),
        ]
        seeds = entities_to_seeds(entities, set())
        assert len(seeds) == 2


class TestEntitiesToSeedsEdgeCases:
    """Edge cases and boundary conditions."""

    def test_empty_input(self) -> None:
        seeds = entities_to_seeds([], set())
        assert seeds == []

    def test_empty_canonical_identifier_is_skipped(self) -> None:
        entity = _make_entity("domain", "")
        seeds = entities_to_seeds([entity], set())
        assert seeds == []

    def test_whitespace_only_identifier_is_skipped(self) -> None:
        entity = _make_entity("domain", "   ")
        seeds = entities_to_seeds([entity], set())
        assert seeds == []

    def test_entity_type_case_insensitive(self) -> None:
        entity = _make_entity("Domain", "example.com")
        seeds = entities_to_seeds([entity], set())
        assert len(seeds) == 1
        assert seeds[0].seed_type == SeedType.DOMAIN

    def test_entity_type_with_whitespace(self) -> None:
        entity = _make_entity("  domain  ", "example.com")
        seeds = entities_to_seeds([entity], set())
        assert len(seeds) == 1

    def test_seed_properties_are_empty_dict(self) -> None:
        """Converted seeds should have empty properties (no entity props leakage)."""
        entity = _make_entity("domain", "example.com", {"some_key": "val"})
        seeds = entities_to_seeds([entity], set())
        assert seeds[0].properties == {}


# ===================================================================
# extract_org_seeds_from_properties
# ===================================================================


class TestExtractOrgSeedsFromProperties:
    """RDAP registrant org extraction from entity properties."""

    def test_registrant_org_key(self) -> None:
        entity = _make_entity(
            "domain", "example.com", {"registrant_org": "Acme Inc"}
        )
        seeds = extract_org_seeds_from_properties([entity], set())
        assert len(seeds) == 1
        assert seeds[0].seed_type == SeedType.ORGANIZATION
        assert seeds[0].value == "Acme Inc"

    def test_underscore_registrant_org_key(self) -> None:
        entity = _make_entity(
            "domain", "example.com", {"_registrant_org": "Beta LLC"}
        )
        seeds = extract_org_seeds_from_properties([entity], set())
        assert len(seeds) == 1
        assert seeds[0].seed_type == SeedType.ORGANIZATION
        assert seeds[0].value == "Beta LLC"

    def test_registrant_org_preferred_over_underscore(self) -> None:
        """When both keys exist, registrant_org is used (checked first)."""
        entity = _make_entity(
            "domain",
            "example.com",
            {"registrant_org": "Primary Org", "_registrant_org": "Alt Org"},
        )
        seeds = extract_org_seeds_from_properties([entity], set())
        assert len(seeds) == 1
        assert seeds[0].value == "Primary Org"

    def test_no_registrant_org_key(self) -> None:
        entity = _make_entity(
            "domain", "example.com", {"other_key": "value"}
        )
        seeds = extract_org_seeds_from_properties([entity], set())
        assert seeds == []

    def test_already_scanned_org_excluded(self) -> None:
        entity = _make_entity(
            "domain", "example.com", {"registrant_org": "Acme Inc"}
        )
        already = {("organization", "Acme Inc")}
        seeds = extract_org_seeds_from_properties([entity], already)
        assert seeds == []

    def test_deduplication_across_entities(self) -> None:
        """Two entities with the same registrant_org produce only one seed."""
        entities = [
            _make_entity("domain", "a.com", {"registrant_org": "Same Org"}),
            _make_entity("domain", "b.com", {"registrant_org": "Same Org"}),
        ]
        seeds = extract_org_seeds_from_properties(entities, set())
        assert len(seeds) == 1
        assert seeds[0].value == "Same Org"

    def test_multiple_distinct_orgs(self) -> None:
        entities = [
            _make_entity("domain", "a.com", {"registrant_org": "Org A"}),
            _make_entity("domain", "b.com", {"registrant_org": "Org B"}),
        ]
        seeds = extract_org_seeds_from_properties(entities, set())
        assert len(seeds) == 2
        values = {s.value for s in seeds}
        assert values == {"Org A", "Org B"}

    def test_seed_has_source_property(self) -> None:
        entity = _make_entity(
            "domain", "example.com", {"registrant_org": "Acme Inc"}
        )
        seeds = extract_org_seeds_from_properties([entity], set())
        assert seeds[0].properties == {"source": "rdap_registrant"}

    def test_works_on_any_entity_type(self) -> None:
        """Org extraction works on IP entities too, not just domains."""
        entity = _make_entity(
            "ip", "192.0.2.1", {"registrant_org": "Network Org"}
        )
        seeds = extract_org_seeds_from_properties([entity], set())
        assert len(seeds) == 1
        assert seeds[0].value == "Network Org"


class TestExtractOrgSeedsEdgeCases:
    """Edge cases for RDAP org extraction."""

    def test_empty_input(self) -> None:
        seeds = extract_org_seeds_from_properties([], set())
        assert seeds == []

    def test_empty_properties(self) -> None:
        entity = _make_entity("domain", "example.com", {})
        seeds = extract_org_seeds_from_properties([entity], set())
        assert seeds == []

    def test_none_org_value_skipped(self) -> None:
        entity = _make_entity(
            "domain", "example.com", {"registrant_org": None}
        )
        seeds = extract_org_seeds_from_properties([entity], set())
        assert seeds == []

    def test_empty_string_org_value_skipped(self) -> None:
        entity = _make_entity(
            "domain", "example.com", {"registrant_org": ""}
        )
        seeds = extract_org_seeds_from_properties([entity], set())
        assert seeds == []

    def test_whitespace_only_org_value_skipped(self) -> None:
        entity = _make_entity(
            "domain", "example.com", {"registrant_org": "   "}
        )
        seeds = extract_org_seeds_from_properties([entity], set())
        assert seeds == []

    def test_non_string_org_value_skipped(self) -> None:
        entity = _make_entity(
            "domain", "example.com", {"registrant_org": 42}
        )
        seeds = extract_org_seeds_from_properties([entity], set())
        assert seeds == []

    def test_non_dict_properties_skipped(self) -> None:
        """If properties is somehow not a dict, skip gracefully."""
        entity = _make_entity("domain", "example.com")
        # Force a non-dict (bypassing type checking — defensive test).
        object.__setattr__(entity, "properties", None)
        seeds = extract_org_seeds_from_properties([entity], set())
        assert seeds == []
