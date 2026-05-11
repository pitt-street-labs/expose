"""Deterministic seed expansion — Stage 1 of the EXPOSE pipeline (SPEC §2.2).

Given operator-provided seeds, ``expand_seeds`` generates additional derived
seeds from deterministic string-transform rules. This stage is entirely
side-effect free and does not touch the network or the database.

Expansion rules (per SPEC §2.2.1):

- **Domain seeds:** If the value is an apex domain (no ``www.`` prefix),
  generate a ``www.{domain}`` variant. If it already starts with ``www.``,
  skip to avoid ``www.www.`` nonsense.
- **Organization seeds:** Generate lowercase, dash-separated, and no-space
  brand-string variants. These are simple string transforms — the LLM
  enrichment layer (Stage 5, out of scope) may produce additional variants.
- **IP seeds:** Passed through unchanged. Single-host expansion is not useful
  and per-IP expansion of large ranges is dangerous at scale.
- **CIDR seeds:** Passed through unchanged. The CIDR itself is a valid seed;
  per-host expansion is the collector's responsibility if required.
- **All other seed types:** Passed through unchanged.

All generated domain values pass through ``canonicalize_domain`` from the
sanitization layer (SPEC §7.2) so the graph never sees uncanonicalized input
even from internal expansion.
"""

from __future__ import annotations

import re

from expose.collectors.base import Seed, SeedType
from expose.sanitization.canonicalize import canonicalize_domain

# TLDs to probe when generating domain seeds from organization names.
# .gov is included for federal-customer trajectory (issue #83).
_COMMON_TLDS = [
    ".com",
    ".net",
    ".org",
    ".io",
    ".cloud",
    ".dev",
    ".ai",
    ".co",
    ".us",
    ".gov",
]

# Corporate suffixes stripped before slug generation so
# "Acme Technologies Inc." -> slug "acme-technologies" / "acmetechnologies",
# not "acmetechnologiesinc".
_ORG_SUFFIXES_RE = re.compile(
    r"\s*\b(?:Inc\.?|Corp\.?|LLC|Ltd\.?|L\.?P\.?|PLC"
    r"|Software|Technologies|Technology|Systems|Solutions"
    r"|Group|Holdings|Enterprises?|Services|International)\s*$",
    re.IGNORECASE,
)


def _is_apex_domain(domain: str) -> bool:
    """Return True if ``domain`` looks like an apex (no ``www.`` prefix).

    This is a syntactic heuristic, not a DNS query. A domain with two labels
    (``example.com``) or more labels without a ``www.`` prefix is treated as
    apex for expansion purposes.
    """
    return not domain.lower().startswith("www.")


def _expand_domain_seed(seed: Seed) -> list[Seed]:
    """Generate ``www.`` variant for apex domain seeds."""
    domain = seed.value.strip().lower()
    if not _is_apex_domain(domain):
        return []
    www_domain = canonicalize_domain(f"www.{domain}")
    return [
        Seed(
            seed_type=SeedType.DOMAIN,
            value=www_domain,
            properties=seed.properties,
        )
    ]


def _strip_org_suffix(name: str) -> str:
    """Strip common corporate suffixes from an organization name.

    ``"CyberArk Software Ltd."`` -> ``"CyberArk"``
    ``"Acme Corp"`` -> ``"Acme"``

    If stripping would leave an empty string, the original is returned.
    """
    stripped = _ORG_SUFFIXES_RE.sub("", name).strip()
    return stripped if stripped else name


def _org_name_to_slugs(raw: str) -> list[str]:
    """Derive deduplicated domain-slug variants from an org name.

    For ``"Cyber Ark Software Inc."`` produces slugs like:
    ``["cyberark", "cyber-ark", "cyberarksoftwareinc", "cyber-ark-software-inc"]``

    Suffix-stripped variants come first (they are more likely to be real
    registered domains), followed by full-name variants that include the
    corporate suffix.
    """
    slugs: list[str] = []
    seen: set[str] = set()

    def _add(slug: str) -> None:
        if slug and slug not in seen:
            seen.add(slug)
            slugs.append(slug)

    lowercase = raw.lower()

    # Suffix-stripped variants first (higher signal).
    stripped = _strip_org_suffix(raw).lower()
    if stripped != lowercase:
        _add(re.sub(r"[^a-z0-9]", "", stripped))
        _add(re.sub(r"[^a-z0-9]+", "-", stripped).strip("-"))

    # Full-name variants (may be identical to stripped for orgs without suffixes).
    _add(re.sub(r"[^a-z0-9]", "", lowercase))    # concatenated
    _add(re.sub(r"[^a-z0-9]+", "-", lowercase).strip("-"))  # dash-separated

    return slugs


def _generate_org_domain_seeds(
    seed: Seed, *, max_domains: int = 30,
) -> list[Seed]:
    """Generate DOMAIN seeds from an ORGANIZATION seed.

    Combines org-name slug variants with ``_COMMON_TLDS``.  The total
    number of generated domains is capped at ``max_domains`` to avoid
    overwhelming the pipeline.  No DNS pre-check is performed — collectors
    already handle failures gracefully.
    """
    raw = seed.value.strip()
    if not raw:
        return []

    slugs = _org_name_to_slugs(raw)
    domains: list[Seed] = []
    seen: set[str] = set()

    for slug in slugs:
        for tld in _COMMON_TLDS:
            if len(domains) >= max_domains:
                return domains
            domain = f"{slug}{tld}"
            if domain not in seen:
                seen.add(domain)
                domains.append(
                    Seed(
                        seed_type=SeedType.DOMAIN,
                        value=domain,
                        properties=seed.properties,
                    )
                )

    return domains


def _expand_organization_seed(seed: Seed) -> list[Seed]:
    """Generate brand-string variants and domain seeds for organization seeds.

    Organization string transforms:
    - Lowercase (``Acme Corp`` -> ``acme corp``)
    - Dash-separated (``Acme Corp`` -> ``acme-corp``)
    - No-space / concatenated (``Acme Corp`` -> ``acmecorp``)

    Domain expansion (issue #83):
    - Generates DOMAIN seeds by combining org-name slugs with common TLDs.
    - Strips corporate suffixes (Inc, Corp, Ltd, etc.) to produce
      additional slug variants before TLD expansion.
    - Capped at ~30 domain seeds to avoid pipeline overload.

    Deduplication happens at the caller level; this function may produce
    variants that are identical to the original (e.g., a single-word org
    name with no spaces yields identical dash and no-space forms).
    """
    raw = seed.value.strip()
    if not raw:
        return []

    lowercase = raw.lower()
    dash_separated = lowercase.replace(" ", "-")
    no_space = lowercase.replace(" ", "")

    variants: list[Seed] = []
    seen = {lowercase}  # track within this expansion to avoid intra-seed dupes

    for variant in (dash_separated, no_space):
        if variant not in seen:
            seen.add(variant)
            variants.append(
                Seed(
                    seed_type=SeedType.ORGANIZATION,
                    value=variant,
                    properties=seed.properties,
                )
            )

    # Multi-TLD domain generation (issue #83).
    variants.extend(_generate_org_domain_seeds(seed))

    return variants


def expand_seeds(seeds: list[Seed]) -> list[Seed]:
    """Deterministic Stage 1 seed expansion.

    Returns the original seeds plus any generated variants, deduplicated by
    ``(seed_type, value)`` tuple. Order is preserved: originals first, then
    generated variants in the order they were produced.

    This function is pure — no I/O, no side effects, fully deterministic.
    """
    if not seeds:
        return []

    # Track seen (seed_type, value) pairs for deduplication
    seen: set[tuple[str, str]] = set()
    result: list[Seed] = []

    def _add(seed: Seed) -> None:
        key = (seed.seed_type.value, seed.value.strip().lower())
        if key not in seen:
            seen.add(key)
            result.append(seed)

    # Pass 1: add all originals
    for seed in seeds:
        _add(seed)

    # Pass 2: expand and add generated variants
    for seed in seeds:
        if seed.seed_type == SeedType.DOMAIN:
            for expanded in _expand_domain_seed(seed):
                _add(expanded)
        elif seed.seed_type == SeedType.ORGANIZATION:
            for expanded in _expand_organization_seed(seed):
                _add(expanded)
        # IP, CIDR, and other types: no expansion — passed through in pass 1

    return result


__all__ = [
    "_COMMON_TLDS",
    "_generate_org_domain_seeds",
    "_org_name_to_slugs",
    "_strip_org_suffix",
    "expand_seeds",
]
