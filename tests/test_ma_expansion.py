"""Tests for M&A seed expansion (issue #53).

Exercises ``expand_ma_seeds`` and the supporting Pydantic models.
No I/O — all tests operate on in-memory Observation objects.

Coverage:

1.  expand_ma_seeds with valid observations -> domain seeds generated
2.  expand_ma_seeds with config disabled -> empty list
3.  Max depth 0 -> no expansion
4.  Max depth 1 -> direct acquisitions only (domain seeds, no org seeds)
5.  Max depth 2 -> also generates organization seeds for recursive expansion
6.  Max acquisitions cap respected
7.  AcquisitionRecord model validation (frozen, bounds)
8.  MAExpansionConfig defaults
9.  Empty observations -> empty seeds
10. Non-MA observations ignored
11. Confidence propagated from observation
12. Attribution source is "transitive_ma"
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import ValidationError

from expose.collectors.base import (
    Observation,
    ObservationSubject,
    ObservationType,
    SeedType,
)
from expose.pipeline.ma_expansion import (
    AcquisitionRecord,
    MAExpansionConfig,
    expand_ma_seeds,
)
from expose.types.canonical import IdentifierType

TENANT_ID = UUID("018f1f00-0000-7000-8000-0000000e0f01")


def _make_ma_observation(
    acquired_org: str = "Venafi",
    acquired_domains: list[str] | None = None,
    acquisition_date: str | None = "2024-06-15",
    parent_org: str = "CyberArk",
    confidence: float = 0.8,
) -> Observation:
    """Build a synthetic ma-discovery observation for testing."""
    if acquired_domains is None:
        acquired_domains = ["venafi.com"]
    return Observation(
        collector_id="ma-discovery",
        collector_version="0.1.0",
        tenant_id=TENANT_ID,
        observation_type=ObservationType.SCANNER_HOST,
        subject=ObservationSubject(
            identifier_type=IdentifierType.DOMAIN,
            identifier_value=parent_org.lower(),
        ),
        observed_at=datetime.now(tz=UTC),
        structured_payload={
            "_collector_id": "ma-discovery",
            "source": "wikidata",
            "source_url": "http://www.wikidata.org/entity/Q123",
            "relationship_type": "acquired_by",
            "parent_organization": parent_org,
            "acquired_organization": acquired_org,
            "acquisition_date": acquisition_date,
            "acquired_domains": acquired_domains,
            "confidence": confidence,
            "attribution_source": "transitive_ma",
        },
    )


def _make_non_ma_observation() -> Observation:
    """Build a non-MA observation (e.g., from github-exposed)."""
    return Observation(
        collector_id="github-exposed",
        collector_version="0.1.0",
        tenant_id=TENANT_ID,
        observation_type=ObservationType.SCANNER_HOST,
        subject=ObservationSubject(
            identifier_type=IdentifierType.DOMAIN,
            identifier_value="example.com",
        ),
        observed_at=datetime.now(tz=UTC),
        structured_payload={
            "source": "github",
            "search_type": "repository",
            "total_results": 5,
        },
    )


# ======================================================================
# 1. Valid observations -> domain seeds generated
# ======================================================================
class TestBasicExpansion:
    def test_valid_observations_produce_domain_seeds(self) -> None:
        obs = [_make_ma_observation()]
        seeds = expand_ma_seeds(obs)

        assert len(seeds) == 1
        assert seeds[0].seed_type == SeedType.DOMAIN
        assert seeds[0].value == "venafi.com"

    def test_multiple_domains_produce_multiple_seeds(self) -> None:
        obs = [
            _make_ma_observation(
                acquired_domains=["venafi.com", "venafi.io"]
            )
        ]
        seeds = expand_ma_seeds(obs)

        assert len(seeds) == 2
        values = {s.value for s in seeds}
        assert "venafi.com" in values
        assert "venafi.io" in values

    def test_multiple_acquisitions_produce_seeds(self) -> None:
        obs = [
            _make_ma_observation(acquired_org="Venafi", acquired_domains=["venafi.com"]),
            _make_ma_observation(acquired_org="Zilla", acquired_domains=["zilla.com"]),
        ]
        seeds = expand_ma_seeds(obs)

        assert len(seeds) == 2
        values = {s.value for s in seeds}
        assert "venafi.com" in values
        assert "zilla.com" in values


# ======================================================================
# 2. Config disabled -> empty list
# ======================================================================
class TestDisabled:
    def test_disabled_returns_empty(self) -> None:
        config = MAExpansionConfig(enabled=False)
        obs = [_make_ma_observation()]
        seeds = expand_ma_seeds(obs, config)
        assert seeds == []


# ======================================================================
# 3. Max depth 0 -> no expansion
# ======================================================================
class TestDepthZero:
    def test_depth_zero_returns_empty(self) -> None:
        config = MAExpansionConfig(max_depth=0)
        obs = [_make_ma_observation()]
        seeds = expand_ma_seeds(obs, config)
        assert seeds == []


# ======================================================================
# 4. Max depth 1 -> direct acquisitions only (no org seeds)
# ======================================================================
class TestDepthOne:
    def test_depth_one_produces_domain_seeds_only(self) -> None:
        config = MAExpansionConfig(max_depth=1)
        obs = [_make_ma_observation()]
        seeds = expand_ma_seeds(obs, config)

        assert all(s.seed_type == SeedType.DOMAIN for s in seeds)
        org_seeds = [s for s in seeds if s.seed_type == SeedType.ORGANIZATION]
        assert org_seeds == []


# ======================================================================
# 5. Max depth 2 -> also generates organization seeds
# ======================================================================
class TestDepthTwo:
    def test_depth_two_includes_org_seeds(self) -> None:
        config = MAExpansionConfig(max_depth=2)
        obs = [_make_ma_observation()]
        seeds = expand_ma_seeds(obs, config)

        domain_seeds = [s for s in seeds if s.seed_type == SeedType.DOMAIN]
        org_seeds = [s for s in seeds if s.seed_type == SeedType.ORGANIZATION]
        assert len(domain_seeds) == 1
        assert len(org_seeds) == 1
        assert org_seeds[0].value == "Venafi"

    def test_depth_three_also_includes_org_seeds(self) -> None:
        config = MAExpansionConfig(max_depth=3)
        obs = [_make_ma_observation()]
        seeds = expand_ma_seeds(obs, config)

        org_seeds = [s for s in seeds if s.seed_type == SeedType.ORGANIZATION]
        assert len(org_seeds) == 1


# ======================================================================
# 6. Max acquisitions cap
# ======================================================================
class TestMaxAcquisitions:
    def test_max_acquisitions_caps_output(self) -> None:
        config = MAExpansionConfig(max_acquisitions=2)
        obs = [
            _make_ma_observation(acquired_org=f"Corp{i}", acquired_domains=[f"corp{i}.com"])
            for i in range(10)
        ]
        seeds = expand_ma_seeds(obs, config)

        # Only 2 acquisitions processed -> 2 domain seeds.
        assert len(seeds) == 2

    def test_max_acquisitions_of_one(self) -> None:
        config = MAExpansionConfig(max_acquisitions=1)
        obs = [
            _make_ma_observation(acquired_org="A", acquired_domains=["a.com"]),
            _make_ma_observation(acquired_org="B", acquired_domains=["b.com"]),
        ]
        seeds = expand_ma_seeds(obs, config)
        assert len(seeds) == 1


# ======================================================================
# 7. AcquisitionRecord model validation
# ======================================================================
class TestAcquisitionRecordValidation:
    def test_valid_record(self) -> None:
        record = AcquisitionRecord(
            parent_organization="CyberArk",
            acquired_organization="Venafi",
            acquired_domains=["venafi.com"],
            acquisition_date="2024-06-15",
            source="wikidata",
            confidence=0.8,
        )
        assert record.parent_organization == "CyberArk"
        assert record.acquired_organization == "Venafi"
        assert record.confidence == 0.8

    def test_frozen(self) -> None:
        record = AcquisitionRecord(
            parent_organization="CyberArk",
            acquired_organization="Venafi",
            source="wikidata",
            confidence=0.5,
        )
        with pytest.raises(ValidationError):
            record.parent_organization = "Other"  # type: ignore[misc]

    def test_extra_forbid(self) -> None:
        with pytest.raises(ValidationError):
            AcquisitionRecord(
                parent_organization="CyberArk",
                acquired_organization="Venafi",
                source="wikidata",
                confidence=0.5,
                bogus_field="nope",  # type: ignore[call-arg]
            )

    def test_confidence_bounds_low(self) -> None:
        with pytest.raises(ValidationError):
            AcquisitionRecord(
                parent_organization="CyberArk",
                acquired_organization="Venafi",
                source="wikidata",
                confidence=-0.1,
            )

    def test_confidence_bounds_high(self) -> None:
        with pytest.raises(ValidationError):
            AcquisitionRecord(
                parent_organization="CyberArk",
                acquired_organization="Venafi",
                source="wikidata",
                confidence=1.1,
            )

    def test_empty_parent_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AcquisitionRecord(
                parent_organization="",
                acquired_organization="Venafi",
                source="wikidata",
                confidence=0.5,
            )

    def test_empty_acquired_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AcquisitionRecord(
                parent_organization="CyberArk",
                acquired_organization="",
                source="wikidata",
                confidence=0.5,
            )

    def test_default_attribution_source(self) -> None:
        record = AcquisitionRecord(
            parent_organization="CyberArk",
            acquired_organization="Venafi",
            source="wikidata",
            confidence=0.5,
        )
        assert record.attribution_source == "transitive_ma"


# ======================================================================
# 8. MAExpansionConfig defaults
# ======================================================================
class TestMAExpansionConfigDefaults:
    def test_defaults(self) -> None:
        config = MAExpansionConfig()
        assert config.enabled is True
        assert config.max_depth == 1
        assert config.max_acquisitions == 20

    def test_frozen(self) -> None:
        config = MAExpansionConfig()
        with pytest.raises(ValidationError):
            config.enabled = False  # type: ignore[misc]

    def test_extra_forbid(self) -> None:
        with pytest.raises(ValidationError):
            MAExpansionConfig(bogus="nope")  # type: ignore[call-arg]

    def test_max_depth_bounds(self) -> None:
        with pytest.raises(ValidationError):
            MAExpansionConfig(max_depth=4)
        with pytest.raises(ValidationError):
            MAExpansionConfig(max_depth=-1)

    def test_max_acquisitions_bounds(self) -> None:
        with pytest.raises(ValidationError):
            MAExpansionConfig(max_acquisitions=0)
        with pytest.raises(ValidationError):
            MAExpansionConfig(max_acquisitions=101)


# ======================================================================
# 9. Empty observations -> empty seeds
# ======================================================================
class TestEmptyInput:
    def test_empty_list_returns_empty(self) -> None:
        seeds = expand_ma_seeds([])
        assert seeds == []

    def test_none_config_uses_defaults(self) -> None:
        seeds = expand_ma_seeds([], None)
        assert seeds == []


# ======================================================================
# 10. Non-MA observations ignored
# ======================================================================
class TestNonMAFiltering:
    def test_non_ma_observations_ignored(self) -> None:
        obs = [_make_non_ma_observation()]
        seeds = expand_ma_seeds(obs)
        assert seeds == []

    def test_mixed_observations_only_ma_expanded(self) -> None:
        obs = [
            _make_non_ma_observation(),
            _make_ma_observation(),
            _make_non_ma_observation(),
        ]
        seeds = expand_ma_seeds(obs)
        assert len(seeds) == 1
        assert seeds[0].value == "venafi.com"


# ======================================================================
# 11. Confidence propagated
# ======================================================================
class TestConfidencePropagation:
    def test_confidence_in_seed_properties(self) -> None:
        obs = [_make_ma_observation(confidence=0.9)]
        seeds = expand_ma_seeds(obs)

        assert len(seeds) >= 1
        assert seeds[0].properties["confidence"] == 0.9

    def test_low_confidence_still_propagated(self) -> None:
        obs = [_make_ma_observation(confidence=0.3)]
        seeds = expand_ma_seeds(obs)

        assert seeds[0].properties["confidence"] == 0.3


# ======================================================================
# 12. Attribution source is "transitive_ma"
# ======================================================================
class TestAttributionSource:
    def test_attribution_source_in_seed_properties(self) -> None:
        obs = [_make_ma_observation()]
        seeds = expand_ma_seeds(obs)

        assert len(seeds) >= 1
        assert seeds[0].properties["attribution_source"] == "transitive_ma"

    def test_attribution_source_on_org_seeds_too(self) -> None:
        config = MAExpansionConfig(max_depth=2)
        obs = [_make_ma_observation()]
        seeds = expand_ma_seeds(obs, config)

        org_seeds = [s for s in seeds if s.seed_type == SeedType.ORGANIZATION]
        assert len(org_seeds) == 1
        assert org_seeds[0].properties["attribution_source"] == "transitive_ma"


# ======================================================================
# Edge cases
# ======================================================================
class TestEdgeCases:
    def test_duplicate_domains_deduplicated(self) -> None:
        """Two acquisitions with same domain -> one seed."""
        obs = [
            _make_ma_observation(acquired_org="A", acquired_domains=["same.com"]),
            _make_ma_observation(acquired_org="B", acquired_domains=["same.com"]),
        ]
        seeds = expand_ma_seeds(obs)

        domain_seeds = [s for s in seeds if s.seed_type == SeedType.DOMAIN]
        assert len(domain_seeds) == 1

    def test_empty_domain_list_no_seeds(self) -> None:
        obs = [_make_ma_observation(acquired_domains=[])]
        seeds = expand_ma_seeds(obs)
        assert seeds == []

    def test_whitespace_domain_filtered(self) -> None:
        obs = [_make_ma_observation(acquired_domains=["  "])]
        seeds = expand_ma_seeds(obs)
        assert seeds == []
