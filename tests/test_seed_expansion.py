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
9. Organization seed: multi-TLD domain generation (issue #83).
10. Organization seed: corporate suffix stripping before slug generation.
11. Organization seed: domain count cap.
"""

from __future__ import annotations

from expose.collectors.base import Seed, SeedType
from expose.pipeline.seed_expansion import (
    _COMMON_TLDS,
    _generate_org_domain_seeds,
    _org_name_to_slugs,
    _strip_org_suffix,
    expand_seeds,
)


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
    """Organization seeds produce dash-separated, no-space, and domain variants."""
    result = expand_seeds([_seed(SeedType.ORGANIZATION, "Acme Corp")])
    values = _values(result)
    assert "Acme Corp" in values  # original preserved
    assert "acme-corp" in values  # dash-separated
    assert "acmecorp" in values  # no-space

    # Multi-TLD domain seeds generated (issue #83).
    domain_seeds = [s for s in result if s.seed_type == SeedType.DOMAIN]
    assert len(domain_seeds) > 0
    domain_values = {s.value for s in domain_seeds}
    assert "acmecorp.com" in domain_values
    assert "acmecorp.gov" in domain_values
    assert "acmecorp.io" in domain_values
    # "Corp" stripped -> "acme" slugs also present.
    assert "acme.com" in domain_values
    assert "acme.net" in domain_values


def test_organization_single_word_minimal_expansion() -> None:
    """A single-word org name has no space to transform — only domain variants."""
    result = expand_seeds([_seed(SeedType.ORGANIZATION, "ACME")])
    values = _values(result)
    assert "ACME" in values  # original
    # dash-separated ("acme") and no-space ("acme") both share the same dedup
    # key as the original ("acme"), so no new ORG variants are emitted.
    org_seeds = [s for s in result if s.seed_type == SeedType.ORGANIZATION]
    assert len(org_seeds) == 1
    # But domain seeds are generated across TLDs.
    domain_seeds = [s for s in result if s.seed_type == SeedType.DOMAIN]
    assert len(domain_seeds) == len(_COMMON_TLDS)
    assert "acme.com" in _values(domain_seeds)
    assert "acme.gov" in _values(domain_seeds)


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

    # Organization: original + org variants + domain variants
    assert "Acme Corp" in values
    assert "acme-corp" in values
    # Multi-TLD domain seeds from org expansion
    assert "acmecorp.com" in values
    assert "acme.gov" in values

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


# ======================================================================
# Multi-TLD domain generation from organization seeds (issue #83)
# ======================================================================


def test_org_multi_tld_cyberark() -> None:
    """CyberArk (single word, no suffix) generates domains across all TLDs."""
    result = expand_seeds([_seed(SeedType.ORGANIZATION, "CyberArk")])
    domain_seeds = [s for s in result if s.seed_type == SeedType.DOMAIN]
    domain_values = {s.value for s in domain_seeds}

    for tld in _COMMON_TLDS:
        assert f"cyberark{tld}" in domain_values, f"Missing cyberark{tld}"


def test_org_multi_tld_multi_word() -> None:
    """Multi-word org produces both concatenated and dash-separated slugs."""
    result = expand_seeds([_seed(SeedType.ORGANIZATION, "Cyber Ark")])
    domain_seeds = [s for s in result if s.seed_type == SeedType.DOMAIN]
    domain_values = {s.value for s in domain_seeds}

    # Concatenated slug
    assert "cyberark.com" in domain_values
    assert "cyberark.io" in domain_values
    # Dash-separated slug
    assert "cyber-ark.com" in domain_values
    assert "cyber-ark.net" in domain_values


def test_org_suffix_stripping() -> None:
    """Corporate suffixes are stripped to produce additional slug variants."""
    result = expand_seeds(
        [_seed(SeedType.ORGANIZATION, "Zilla Security Inc.")]
    )
    domain_seeds = [s for s in result if s.seed_type == SeedType.DOMAIN]
    domain_values = {s.value for s in domain_seeds}

    # Suffix-stripped slugs come first (higher signal, within cap).
    assert "zillasecurity.com" in domain_values
    assert "zillasecurity.io" in domain_values
    assert "zilla-security.com" in domain_values
    assert "zilla-security.gov" in domain_values
    # Full-name slugs also present (within the 30-domain cap).
    assert "zillasecurityinc.com" in domain_values


def test_org_suffix_stripping_technologies() -> None:
    """'Technologies' suffix is stripped."""
    result = expand_seeds(
        [_seed(SeedType.ORGANIZATION, "Acme Technologies")]
    )
    domain_seeds = [s for s in result if s.seed_type == SeedType.DOMAIN]
    domain_values = {s.value for s in domain_seeds}

    assert "acmetechnologies.com" in domain_values
    # Stripped variant
    assert "acme.com" in domain_values
    assert "acme.gov" in domain_values


def test_org_domain_cap() -> None:
    """Domain seed generation is capped to avoid pipeline overload."""
    # Use a short cap to verify the limit is respected.
    seed = _seed(SeedType.ORGANIZATION, "Big Mega Super Corp")
    domains = _generate_org_domain_seeds(seed, max_domains=5)
    assert len(domains) <= 5
    assert all(s.seed_type == SeedType.DOMAIN for s in domains)


def test_org_domain_default_cap_respects_limit() -> None:
    """Even with many slug variants, domain count stays within 30."""
    seed = _seed(SeedType.ORGANIZATION, "Big Mega Super Corp")
    domains = _generate_org_domain_seeds(seed)
    assert len(domains) <= 30


def test_strip_org_suffix_preserves_non_suffix() -> None:
    """Org names without recognizable suffixes pass through unchanged."""
    assert _strip_org_suffix("CyberArk") == "CyberArk"
    assert _strip_org_suffix("Cloudflare") == "Cloudflare"


def test_strip_org_suffix_handles_various_suffixes() -> None:
    """Common corporate suffixes are all recognized and stripped."""
    assert _strip_org_suffix("Acme Corp") == "Acme"
    assert _strip_org_suffix("Acme Corp.") == "Acme"
    assert _strip_org_suffix("Acme Inc") == "Acme"
    assert _strip_org_suffix("Acme Inc.") == "Acme"
    assert _strip_org_suffix("Acme Ltd") == "Acme"
    assert _strip_org_suffix("Acme Ltd.") == "Acme"
    assert _strip_org_suffix("Acme LLC") == "Acme"
    assert _strip_org_suffix("Acme Software") == "Acme"
    assert _strip_org_suffix("Acme Technologies") == "Acme"
    assert _strip_org_suffix("Acme Holdings") == "Acme"


def test_org_name_to_slugs_deduplication() -> None:
    """Slug generation deduplicates identical forms."""
    slugs = _org_name_to_slugs("ACME")
    # Single word: concatenated and dash-separated are the same ("acme")
    assert slugs == ["acme"]


def test_org_name_to_slugs_multi_word() -> None:
    """Multi-word org produces distinct concatenated and dashed slugs."""
    slugs = _org_name_to_slugs("Cyber Ark")
    assert "cyberark" in slugs
    assert "cyber-ark" in slugs


def test_org_domain_seeds_have_correct_type() -> None:
    """All generated domain seeds have SeedType.DOMAIN."""
    result = expand_seeds([_seed(SeedType.ORGANIZATION, "Acme Corp")])
    domain_seeds = [s for s in result if s.seed_type == SeedType.DOMAIN]
    for ds in domain_seeds:
        assert ds.seed_type == SeedType.DOMAIN
        assert "." in ds.value  # must be domain-shaped


def test_gov_tld_present_for_federal_trajectory() -> None:
    """.gov TLD is important for federal customer trajectory (issue #83)."""
    assert ".gov" in _COMMON_TLDS
    result = expand_seeds([_seed(SeedType.ORGANIZATION, "CyberArk")])
    domain_values = {s.value for s in result if s.seed_type == SeedType.DOMAIN}
    assert "cyberark.gov" in domain_values


def test_org_empty_value_no_domains() -> None:
    """Empty org seed is passed through but generates no domain seeds."""
    result = expand_seeds([_seed(SeedType.ORGANIZATION, "  ")])
    # The original seed is passed through (Pydantic strips whitespace -> ""),
    # but no expansion (org variants or domain seeds) is generated.
    domain_seeds = [s for s in result if s.seed_type == SeedType.DOMAIN]
    assert domain_seeds == []


def test_org_domain_dedup_with_explicit_domain_seed() -> None:
    """If a domain seed already exists, org expansion doesn't duplicate it."""
    seeds = [
        _seed(SeedType.DOMAIN, "cyberark.com"),
        _seed(SeedType.ORGANIZATION, "CyberArk"),
    ]
    result = expand_seeds(seeds)
    # Count how many times cyberark.com appears
    cyberark_com_count = sum(
        1 for s in result if s.value == "cyberark.com"
    )
    assert cyberark_com_count == 1  # deduplication prevents double
