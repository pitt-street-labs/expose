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

from expose.collectors.base import Seed, SeedType
from expose.sanitization.canonicalize import canonicalize_domain


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


def _expand_organization_seed(seed: Seed) -> list[Seed]:
    """Generate brand-string variants for organization seeds.

    Transforms applied:
    - Lowercase (``Acme Corp`` -> ``acme corp``)
    - Dash-separated (``Acme Corp`` -> ``acme-corp``)
    - No-space / concatenated (``Acme Corp`` -> ``acmecorp``)

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


__all__ = ["expand_seeds"]
