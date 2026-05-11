"""SPF / DKIM / DMARC email authentication policy collector (Tier 1, passive).

This collector queries DNS for email authentication records associated with
a domain seed:

1. **SPF** — ``TXT`` record at ``{domain}`` containing ``v=spf1 ...``
2. **DKIM** — ``TXT`` record at ``{selector}._domainkey.{domain}`` for a set
   of common selectors (``default``, ``google``, ``selector1``, ``selector2``,
   ``k1``, ``s1``, ``s2``, ``dkim``, ``mail``)
3. **DMARC** — ``TXT`` record at ``_dmarc.{domain}``

The output is a single observation per domain combining all three policy
areas. This reveals mail infrastructure, authorized third-party senders
(SPF includes), and potential shadow IT (SaaS platforms authorized to send
as the organization).

Tier 1 / passive: only performs DNS queries against the public authoritative
nameservers for the target domain. No credentials required.

The ``dnspython`` library is an optional dependency (installed via the
``expose[collectors-dns]`` extra). The module imports cleanly when
``dnspython`` is absent; ``expand()`` raises ``CollectorError`` with an
actionable message if invoked without the library.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

from expose.collectors.base import (
    Collector,
    CollectorConfig,
    CollectorError,
    CollectorHealthCheck,
    CollectorSourceUnreachableError,
    Observation,
    ObservationSubject,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.registry import register_collector
from expose.collectors.tiers import CollectorTier
from expose.sanitization.canonicalize import canonicalize_domain
from expose.sanitization.text import SanitizationFieldKind, sanitize_field
from expose.types.canonical import CollectorStatus, ExtendedIdentifierType

try:
    import dns.asyncresolver as _dns_asyncresolver
    import dns.name as _dns_name
    import dns.resolver as _dns_resolver

    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

logger = logging.getLogger(__name__)

# DKIM selectors to probe. These are the most common selectors used by
# major email providers and SaaS platforms. The list is intentionally short
# to keep DNS query volume reasonable for a passive collector.
_DKIM_SELECTORS = (
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "s1",
    "s2",
    "dkim",
    "mail",
)

# Well-known domain used for health checks.
_HEALTH_CHECK_DOMAIN = "dns.google"


def _parse_spf(txt: str) -> dict[str, Any]:
    """Extract SPF includes, mechanisms, and IP directives from an SPF record.

    Returns a dict with ``includes`` (list of include targets),
    ``mechanisms`` (list of all mechanisms after the ``v=spf1`` tag),
    ``ip4_addresses`` (list of ``ip4:`` values), and ``ip6_addresses``
    (list of ``ip6:`` values).
    """
    parts = txt.split()
    includes = [m.split(":", 1)[1] for m in parts if m.startswith("include:")]
    mechanisms = parts[1:]  # skip v=spf1
    ip4_addresses = [
        m.split(":", 1)[1] for m in parts if m.startswith("ip4:")
    ]
    ip6_addresses = [
        m.split(":", 1)[1] for m in parts if m.startswith("ip6:")
    ]
    return {
        "includes": includes,
        "mechanisms": mechanisms,
        "ip4_addresses": ip4_addresses,
        "ip6_addresses": ip6_addresses,
    }


def _parse_dmarc(txt: str) -> dict[str, Any]:
    """Extract DMARC policy and rua from a DMARC record string.

    Returns a dict with ``policy`` (the ``p=`` value) and ``rua`` (the
    ``rua=`` mailto address, or ``None``).
    """
    result: dict[str, Any] = {"policy": None, "rua": None}
    for raw_tag in txt.split(";"):
        stripped = raw_tag.strip()
        if stripped.startswith("p="):
            result["policy"] = stripped[2:].strip()
        elif stripped.startswith("rua="):
            rua_value = stripped[4:].strip()
            if rua_value.startswith("mailto:"):
                rua_value = rua_value[7:]
            result["rua"] = rua_value
    return result


def _txt_from_answer(answer: Any) -> str:
    """Join TXT record data chunks into a single string."""
    return b"".join(answer[0].strings).decode("utf-8", errors="replace")


@register_collector
class EmailAuthCollector(Collector):
    """Collect SPF, DKIM, and DMARC records for a domain seed.

    Tier-1 passive collector. Only performs DNS TXT queries; no
    credentials required.
    """

    collector_id: str = "spf-dkim-dmarc"
    collector_version: str = "0.1.0"
    tier: CollectorTier = CollectorTier.TIER_1
    requires_credentials: bool = False
    rate_limit_per_minute: int | None = None

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)
        if HAS_DNSPYTHON:
            self._resolver = _dns_asyncresolver.Resolver()
            self._resolver.lifetime = config.request_timeout_seconds
        else:
            self._resolver = None  # type: ignore[assignment]

    async def _query_txt(self, name: str) -> str | None:
        """Resolve a TXT record, returning the joined string or None.

        Returns ``None`` for NXDOMAIN and NoAnswer. Raises
        ``CollectorSourceUnreachableError`` for timeouts and other
        network-level failures.
        """
        try:
            answer = await self._resolver.resolve(name, "TXT")
            return _txt_from_answer(answer)
        except (
            _dns_resolver.NXDOMAIN,
            _dns_resolver.NoAnswer,
            _dns_resolver.NoNameservers,
            _dns_name.EmptyLabel,
        ):
            return None
        except _dns_resolver.LifetimeTimeout as exc:
            msg = f"DNS resolution timed out for {name!r}"
            raise CollectorSourceUnreachableError(msg) from exc
        except Exception as exc:
            msg = f"DNS resolution failed for {name!r}: {exc}"
            raise CollectorSourceUnreachableError(msg) from exc

    async def _collect_spf(self, domain: str) -> dict[str, Any]:
        """Query SPF TXT records for ``domain`` and return payload fields."""
        spf_txt_records: list[str] = []
        try:
            answer = await self._resolver.resolve(domain, "TXT")
            for rr in answer:
                txt_val = b"".join(rr.strings).decode("utf-8", errors="replace")
                if txt_val.startswith("v=spf1"):
                    spf_txt_records.append(txt_val)
        except (
            _dns_resolver.NXDOMAIN,
            _dns_resolver.NoAnswer,
            _dns_resolver.NoNameservers,
            _dns_name.EmptyLabel,
        ):
            pass
        except _dns_resolver.LifetimeTimeout as exc:
            msg = f"DNS resolution timed out for {domain!r}"
            raise CollectorSourceUnreachableError(msg) from exc
        except Exception as exc:
            msg = f"DNS resolution failed for {domain!r}: {exc}"
            raise CollectorSourceUnreachableError(msg) from exc

        result: dict[str, Any] = {"has_spf": len(spf_txt_records) > 0}
        if result["has_spf"]:
            spf_record = spf_txt_records[0]
            sanitized = sanitize_field(
                spf_record, SanitizationFieldKind.DNS_TXT_RECORD
            ).value
            parsed = _parse_spf(spf_record)
            result["spf_record"] = sanitized
            result["spf_includes"] = parsed["includes"]
            result["spf_mechanisms"] = parsed["mechanisms"]
            result["spf_ip4_addresses"] = parsed["ip4_addresses"]
            result["spf_ip6_addresses"] = parsed["ip6_addresses"]
        return result

    async def _collect_dkim(self, domain: str) -> dict[str, Any]:
        """Probe common DKIM selectors for ``domain`` and return payload fields."""
        selectors_found: list[str] = []
        records: dict[str, str] = {}
        for selector in _DKIM_SELECTORS:
            dkim_name = f"{selector}._domainkey.{domain}"
            raw = await self._query_txt(dkim_name)
            if raw is not None and "DKIM1" in raw:
                sanitized = sanitize_field(
                    raw, SanitizationFieldKind.DNS_TXT_RECORD
                ).value
                selectors_found.append(selector)
                records[selector] = sanitized

        return {
            "dkim_selectors_found": selectors_found,
            "dkim_records": records,
            "has_dkim": len(selectors_found) > 0,
        }

    async def _collect_dmarc(self, domain: str) -> dict[str, Any]:
        """Query the DMARC record for ``domain`` and return payload fields."""
        dmarc_raw = await self._query_txt(f"_dmarc.{domain}")
        has_dmarc = dmarc_raw is not None and dmarc_raw.startswith("v=DMARC1")
        result: dict[str, Any] = {"has_dmarc": has_dmarc}
        if has_dmarc and dmarc_raw is not None:
            result["dmarc_record"] = sanitize_field(
                dmarc_raw, SanitizationFieldKind.DNS_TXT_RECORD
            ).value
            parsed = _parse_dmarc(dmarc_raw)
            result["dmarc_policy"] = parsed["policy"]
            result["dmarc_rua"] = parsed["rua"]
        return result

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Query SPF, DKIM, and DMARC records for a DOMAIN seed.

        Skips non-DOMAIN seeds. On DNS timeout or resolver failure,
        raises ``CollectorSourceUnreachableError``. Yields a single
        observation combining all three email auth policy areas.
        """
        if not HAS_DNSPYTHON:
            msg = "dnspython not installed; install expose[collectors-dns]"
            raise CollectorError(msg)

        if seed.seed_type != SeedType.DOMAIN:
            return

        domain = seed.value
        canonical = canonicalize_domain(domain)

        payload: dict[str, Any] = {"record_type": "email_auth_policy"}
        payload.update(await self._collect_spf(domain))
        payload.update(await self._collect_dkim(domain))
        payload.update(await self._collect_dmarc(domain))

        yield Observation(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            tenant_id=self.config.tenant_id,
            observation_type=ObservationType.DNS_RECORD,
            subject=ObservationSubject(
                identifier_type=ExtendedIdentifierType.DOMAIN,
                identifier_value=canonical,
            ),
            observed_at=datetime.now(UTC),
            structured_payload=payload,
        )

        # Emit separate IP observations for each ip4:/ip6: directive found
        # in the SPF record.  These feed the iterative expansion loop:
        # domain -> SPF IPs -> BGP/Shodan on those IPs.
        for ip_val in payload.get("spf_ip4_addresses", []):
            # Strip CIDR suffix for the identifier value (keep the raw
            # value with CIDR in the payload for context).
            ip_bare = ip_val.split("/")[0]
            yield Observation(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                tenant_id=self.config.tenant_id,
                observation_type=ObservationType.DNS_RECORD,
                subject=ObservationSubject(
                    identifier_type=ExtendedIdentifierType.IP,
                    identifier_value=ip_bare,
                ),
                observed_at=datetime.now(UTC),
                structured_payload={
                    "source": "spf_record",
                    "domain": canonical,
                    "mechanism": "ip4",
                    "raw_value": ip_val,
                },
            )

        for ip_val in payload.get("spf_ip6_addresses", []):
            ip_bare = ip_val.split("/")[0]
            yield Observation(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                tenant_id=self.config.tenant_id,
                observation_type=ObservationType.DNS_RECORD,
                subject=ObservationSubject(
                    identifier_type=ExtendedIdentifierType.IP,
                    identifier_value=ip_bare,
                ),
                observed_at=datetime.now(UTC),
                structured_payload={
                    "source": "spf_record",
                    "domain": canonical,
                    "mechanism": "ip6",
                    "raw_value": ip_val,
                },
            )

    async def health_check(self) -> CollectorHealthCheck:
        """Probe DNS resolution by resolving a well-known domain.

        Returns a ``CollectorHealthCheck`` with SUCCESS or FAILURE
        status. Does not raise.
        """
        if not HAS_DNSPYTHON:
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=datetime.now(UTC),
                error_message="dnspython not installed; install expose[collectors-dns]",
            )

        start = datetime.now(UTC)
        try:
            await self._resolver.resolve(_HEALTH_CHECK_DOMAIN, "A")
            elapsed_ms = (datetime.now(UTC) - start).total_seconds() * 1000
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.SUCCESS,
                checked_at=start,
                latency_ms=elapsed_ms,
            )
        except Exception as exc:
            elapsed_ms = (datetime.now(UTC) - start).total_seconds() * 1000
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=start,
                latency_ms=elapsed_ms,
                error_message=str(exc),
            )


__all__ = [
    "HAS_DNSPYTHON",
    "EmailAuthCollector",
]
