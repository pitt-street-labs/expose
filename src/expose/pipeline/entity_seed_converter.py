"""Convert discovered entities into typed seeds for iterative pipeline expansion.

After the initial pipeline run discovers entities (domains, IPs, orgs, etc.),
this module converts them back into ``Seed`` objects so the dispatcher can
schedule follow-up collection passes. This is the feedback loop that makes
EXPOSE's iterative expansion work: discover entity -> convert to seed ->
collect more observations -> discover more entities -> repeat until scope
exhaustion.

The module also provides a helper to extract organization names from RDAP
registrant data stored in entity properties, which is a common source of
new organization seeds.

Entity type -> SeedType mapping:
- ``"domain"``, ``"subdomain"`` -> ``SeedType.DOMAIN``
- ``"ip"``, ``"ip_address"`` -> ``SeedType.IP``
- ``"cidr"`` -> ``SeedType.CIDR``
- ``"organization"`` -> ``SeedType.ORGANIZATION``
- ``"cloud_resource_id"`` -> skipped (not directly scannable)
- ``"certificate"`` -> skipped
"""

from __future__ import annotations

import logging
from collections.abc import Sequence

from expose.collectors.base import Seed, SeedType
from expose.db.models import Entity

logger = logging.getLogger(__name__)

# Entity types that cannot be directly converted to seeds — they require
# specialized handling or are not directly scannable.
_SKIP_ENTITY_TYPES: frozenset[str] = frozenset({
    "cloud_resource_id",
    "certificate",
})

# Map from entity_type string to SeedType.  Entity types not present here
# and not in _SKIP_ENTITY_TYPES will be logged as unmapped and skipped.
_ENTITY_TYPE_TO_SEED_TYPE: dict[str, SeedType] = {
    "domain": SeedType.DOMAIN,
    "subdomain": SeedType.DOMAIN,
    "ip": SeedType.IP,
    "ip_address": SeedType.IP,
    "cidr": SeedType.CIDR,
    "organization": SeedType.ORGANIZATION,
}

# Property keys that may hold RDAP registrant organization names.
# The RDAP collector stores it as ``registrant_org`` in the observation
# structured_payload (see ``rdap_whois.py`` ``_parse_rdap_response``).
# Entity properties may also carry the key with a leading underscore from
# earlier pipeline stages, so we check both.
_REGISTRANT_ORG_KEYS: tuple[str, ...] = ("registrant_org", "_registrant_org")


def _extract_apex_domains(seeds: Sequence[Seed]) -> frozenset[str]:
    """Extract apex domains from a set of seeds for scope anchoring.

    Given seeds like ``["sub.example.com", "www.example.com", "192.168.1.1"]``,
    returns ``frozenset({"example.com"})``.
    """
    apex: set[str] = set()
    for seed in seeds:
        if seed.seed_type != SeedType.DOMAIN:
            continue
        parts = seed.value.strip().lower().split(".")
        if len(parts) >= 2:
            apex.add(".".join(parts[-2:]))
    return frozenset(apex)


def _extract_org_names(seeds: Sequence[Seed]) -> frozenset[str]:
    """Extract organization-like names from original seeds for scope anchoring.

    Collects explicit org seeds and derives org names from domain seeds
    (e.g., ``example.com`` yields ``example``).
    """
    names: set[str] = set()
    for seed in seeds:
        val = seed.value.strip().lower()
        if seed.seed_type == SeedType.ORGANIZATION:
            names.add(val)
        elif seed.seed_type == SeedType.DOMAIN:
            parts = val.split(".")
            if len(parts) >= 2:
                names.add(parts[-2])
    return frozenset(names)


def _is_in_scope(
    value: str,
    seed_type: SeedType,
    apex_domains: frozenset[str],
    org_names: frozenset[str] | None = None,
) -> bool:
    """Check whether a candidate seed is anchored to the original scope.

    Domain seeds must share an apex domain with the original seeds.
    Organization seeds must match an original org name or domain label.
    IP and CIDR seeds pass through (controlled by other filters).
    """
    if not apex_domains:
        return True
    if seed_type == SeedType.DOMAIN:
        parts = value.strip().lower().split(".")
        if len(parts) >= 2:
            candidate_apex = ".".join(parts[-2:])
            return candidate_apex in apex_domains
        return False
    if seed_type == SeedType.ORGANIZATION and org_names:
        return value.strip().lower() in org_names
    if seed_type in (SeedType.IP, SeedType.CIDR):
        return True
    return seed_type != SeedType.ORGANIZATION


def entities_to_seeds(
    entities: Sequence[Entity],
    already_scanned: set[tuple[str, str]],
    *,
    anchor_seeds: Sequence[Seed] | None = None,
) -> list[Seed]:
    """Convert entities to typed seeds, excluding already-scanned pairs.

    Parameters
    ----------
    entities:
        Sequence of ``Entity`` ORM instances to convert.
    already_scanned:
        Set of ``(seed_type_value, canonical_identifier)`` pairs that have
        already been dispatched to collectors.  Seeds matching a pair in this
        set are silently skipped to avoid redundant work.
    anchor_seeds:
        Original operator-provided seeds used for scope anchoring.  When
        provided, domain entities are only promoted to seeds if they share
        an apex domain with the originals.  This prevents transitive
        discoveries (e.g., ISP domains found via SPF chain following or
        BGP lookups) from polluting the scan with unrelated infrastructure.

    Returns
    -------
    list[Seed]
        Deduplicated list of seeds ready for dispatch.  Order follows the
        input entity sequence; first occurrence wins when deduplicating.
    """
    apex_domains = _extract_apex_domains(anchor_seeds) if anchor_seeds else frozenset()
    org_names = _extract_org_names(anchor_seeds) if anchor_seeds else frozenset()

    seeds: list[Seed] = []
    seen: set[tuple[str, str]] = set()

    for entity in entities:
        entity_type = entity.entity_type.lower().strip()

        # Skip entity types that are not directly scannable.
        if entity_type in _SKIP_ENTITY_TYPES:
            continue

        seed_type = _ENTITY_TYPE_TO_SEED_TYPE.get(entity_type)
        if seed_type is None:
            logger.debug(
                "Unmapped entity type %r for entity %s — skipping",
                entity.entity_type,
                entity.canonical_identifier,
            )
            continue

        value = entity.canonical_identifier.strip()
        if not value:
            continue

        key = (seed_type.value, value)

        # Skip if already scanned or already seen in this batch.
        if key in already_scanned or key in seen:
            continue

        # Scope anchor check: reject entities that aren't anchored to
        # the original seeds.
        if not _is_in_scope(value, seed_type, apex_domains, org_names):
            logger.debug(
                "Scope filter: rejecting %s %r — not anchored to original seeds",
                seed_type.value,
                value,
            )
            continue

        seen.add(key)
        # Carry the entity's attribution_status into the seed properties
        # so Tier-3 dispatch gates can evaluate pass 2+ seeds correctly
        # without requiring a separate DB lookup.
        seed_props: dict[str, str] = {}
        if hasattr(entity, "attribution_status") and entity.attribution_status:
            seed_props["attribution_status"] = entity.attribution_status
        seeds.append(
            Seed(
                seed_type=seed_type,
                value=value,
                properties=seed_props,
            )
        )

    return seeds


def extract_org_seeds_from_properties(
    entities: Sequence[Entity],
    already_scanned: set[tuple[str, str]],
) -> list[Seed]:
    """Extract organization names from RDAP registrant data in entity properties.

    Looks for ``registrant_org`` or ``_registrant_org`` in entity properties
    and creates ``ORGANIZATION`` seeds for discovered org names.  This is a
    secondary seed source — the RDAP collector stores the registrant org in
    the observation payload, which the dispatcher may copy into entity
    properties during graph upsert.

    Parameters
    ----------
    entities:
        Sequence of ``Entity`` ORM instances to inspect.
    already_scanned:
        Set of ``(seed_type_value, canonical_identifier)`` pairs that have
        already been dispatched.

    Returns
    -------
    list[Seed]
        Deduplicated list of ``ORGANIZATION`` seeds extracted from properties.
    """
    seeds: list[Seed] = []
    seen: set[str] = set()

    for entity in entities:
        props = entity.properties
        if not props or not isinstance(props, dict):
            continue

        for key in _REGISTRANT_ORG_KEYS:
            org_name = props.get(key)
            if not org_name or not isinstance(org_name, str):
                continue

            org_name = org_name.strip()
            if not org_name:
                continue

            # Deduplicate within this batch and against already-scanned.
            scan_key = (SeedType.ORGANIZATION.value, org_name)
            if org_name in seen or scan_key in already_scanned:
                continue

            seen.add(org_name)
            seeds.append(
                Seed(
                    seed_type=SeedType.ORGANIZATION,
                    value=org_name,
                    properties={"source": "rdap_registrant"},
                )
            )
            # Found an org from this entity — no need to check more keys.
            break

    return seeds


def filter_seeds_by_scope(
    seeds: list[Seed],
    anchor_seeds: Sequence[Seed],
) -> list[Seed]:
    """Remove seeds that fall outside the original scope.

    Applies the same scope check used by ``entities_to_seeds``
    to an arbitrary seed list. Use this as a final gate after ``expand_seeds``
    to catch domains and org names introduced by org-seed expansion or M&A
    expansion that don't relate to the original target.
    """
    apex_domains = _extract_apex_domains(anchor_seeds)
    org_names = _extract_org_names(anchor_seeds)
    if not apex_domains and not org_names:
        return seeds
    result = []
    for seed in seeds:
        if seed.properties.get("source") == "ma_expansion":
            result.append(seed)
        elif _is_in_scope(seed.value, seed.seed_type, apex_domains, org_names):
            result.append(seed)
        else:
            logger.debug(
                "Scope filter (post-expand): rejecting %s %r",
                seed.seed_type.value,
                seed.value,
            )
    return result


__all__ = [
    "entities_to_seeds",
    "extract_org_seeds_from_properties",
    "filter_seeds_by_scope",
    "_extract_apex_domains",
    "_is_in_scope",
]
