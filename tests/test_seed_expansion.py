"""Tests for deterministic seed expansion (Stage 1 of the EXPOSE pipeline).

Coverage:

1. Domain seed: apex domain generates a ``www.`` variant.
2. Domain seed: ``www.example.com`` does NOT generate ``www.www.example.com``.
3. Organization seed: generates lowercase/dash/no-space variants.
4. IP seed: passed through unchanged (no expansion).
5. CIDR seed: passed through unchanged (no expansion).
6. Deduplication: duplicate seeds in input produce deduplicated output.
7. Empty input: returns empty list.
8. Mixed seed types: all expansion rules fire correctly in one call.
"""

from __future__ import annotations

from expose.collectors.base import Seed, SeedType
from expose.pipeline.seed_expansion import expand_seeds


def _seed(seed_type: SeedType, value: str) -> Seed:
    """Convenience factory for test seeds."""
    return Seed(seed_type=seed_type, value=value)


def _values(seeds: list[Seed]) -> list[str]:
    """Extract values for assertion readability."""
    return [s.value for s in seeds]


def test_domain_apex_generates_www_variant() -> None:
    """An apex domain like ``example.com`` should generate ``www.example.com``."""
    result = expand_seeds([_seed(SeedType.DOMAIN, "example.com")])
    values = _values(result)
    assert "example.com" in values
    assert "www.example.com" in values
    assert len(result) == 2


def test_domain_www_does_not_generate_www_www() -> None:
    """A domain starting with ``www.`` must not produce ``www.www.`` variants."""
    result = expand_seeds([_seed(SeedType.DOMAIN, "www.example.com")])
    values = _values(result)
    assert "www.example.com" in values
    # Must NOT contain www.www.example.com
    assert all("www.www." not in v for v in values)
    assert len(result) == 1


def test_organization_generates_brand_variants() -> None:
    """Organization seeds produce dash-separated and no-space variants."""
    result = expand_seeds([_seed(SeedType.ORGANIZATION, "Acme Corp")])
    values = _values(result)
    assert "Acme Corp" in values  # original preserved
    assert "acme-corp" in values  # dash-separated
    assert "acmecorp" in values  # no-space
    # "acme corp" (lowercase) shares the same dedup key as the original,
    # so it is not emitted as a separate seed.
    assert len(result) == 3


def test_organization_single_word_minimal_expansion() -> None:
    """A single-word org name has no space to transform — no new variants."""
    result = expand_seeds([_seed(SeedType.ORGANIZATION, "ACME")])
    values = _values(result)
    assert "ACME" in values  # original
    # dash-separated ("acme") and no-space ("acme") both share the same dedup
    # key as the original ("acme"), so no new variants are emitted.
    assert len(result) == 1


def test_ip_seed_passed_through_unchanged() -> None:
    """IP seeds have no expansion rules — returned as-is."""
    result = expand_seeds([_seed(SeedType.IP, "192.0.2.1")])
    assert len(result) == 1
    assert result[0].value == "192.0.2.1"
    assert result[0].seed_type == SeedType.IP


def test_cidr_seed_passed_through_unchanged() -> None:
    """CIDR seeds have no expansion rules — returned as-is."""
    result = expand_seeds([_seed(SeedType.CIDR, "198.51.100.0/24")])
    assert len(result) == 1
    assert result[0].value == "198.51.100.0/24"
    assert result[0].seed_type == SeedType.CIDR


def test_deduplication_removes_duplicate_seeds() -> None:
    """Duplicate seeds in input are deduplicated in output."""
    seeds = [
        _seed(SeedType.DOMAIN, "example.com"),
        _seed(SeedType.DOMAIN, "example.com"),  # duplicate
        _seed(SeedType.DOMAIN, "EXAMPLE.COM"),  # case-insensitive dupe
    ]
    result = expand_seeds(seeds)
    # Should have: example.com + www.example.com (generated), all dupes removed
    assert len(result) == 2
    values = _values(result)
    assert "example.com" in values
    assert "www.example.com" in values


def test_empty_input_returns_empty() -> None:
    """Empty seed list returns empty list."""
    result = expand_seeds([])
    assert result == []


def test_mixed_seed_types_all_expand_correctly() -> None:
    """A mix of seed types all expand according to their rules."""
    seeds = [
        _seed(SeedType.DOMAIN, "example.com"),
        _seed(SeedType.ORGANIZATION, "Acme Corp"),
        _seed(SeedType.IP, "10.0.0.1"),
        _seed(SeedType.CIDR, "10.0.0.0/8"),
        _seed(SeedType.ASN, "AS64496"),
    ]
    result = expand_seeds(seeds)
    values = _values(result)

    # Domain: original + www variant
    assert "example.com" in values
    assert "www.example.com" in values

    # Organization: original + variants
    assert "Acme Corp" in values
    assert "acme-corp" in values

    # IP, CIDR, ASN: unchanged
    assert "10.0.0.1" in values
    assert "10.0.0.0/8" in values
    assert "AS64496" in values


def test_domain_expansion_canonicalizes() -> None:
    """Generated www. variants pass through canonicalize_domain."""
    result = expand_seeds([_seed(SeedType.DOMAIN, "EXAMPLE.COM")])
    values = _values(result)
    # The www variant should be lowercased by canonicalize_domain
    assert "www.example.com" in values


def test_entity_seed_type_passed_through() -> None:
    """ENTITY seed type (downstream pivot) is passed through unchanged."""
    result = expand_seeds([_seed(SeedType.ENTITY, "some-entity-id")])
    assert len(result) == 1
    assert result[0].seed_type == SeedType.ENTITY
    assert result[0].value == "some-entity-id"
