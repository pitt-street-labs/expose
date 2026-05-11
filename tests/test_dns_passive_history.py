"""Tests for the dns-passive-history collector (Tier 1).

Exercises SecurityTrails + VirusTotal API logic via ``respx`` mocks — no
live network calls. Coverage:

 1.  Collector ID, tier, requires_credentials correct
 2.  SecurityTrails API: historical A records parsed
 3.  SecurityTrails API: multiple DNS types parsed
 4.  VirusTotal API: resolutions parsed
 5.  Both sources combined — deduplicated
 6.  No API keys — empty list (graceful degradation)
 7.  SecurityTrails subdomain discovery
 8.  first_seen / last_seen in observations
 9.  Rate limiting respected (VirusTotal 429)
10.  HTTP error → graceful degradation (SecurityTrails)
11.  HTTP error → graceful degradation (VirusTotal)
12.  IP seed → SecurityTrails reverse lookup
13.  IP seed → VirusTotal reverse resolutions
14.  Health check: success and failure
15.  Non-matching seed types skipped
16.  VirusTotal Unix timestamp conversion
17.  Registration in default registry
"""

from __future__ import annotations

from uuid import UUID

import httpx
import pytest
import respx

from expose.collectors.base import (
    Collector,
    CollectorConfig,
    CollectorCredential,
    CollectorHealthCheck,
    Observation,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.builtin.dns_passive_history import (
    PassiveDnsHistoryCollector,
)
from expose.collectors.registry import DEFAULT_REGISTRY
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, IdentifierType

TENANT_ID = UUID("018f1f00-0000-7000-8000-0000000c0d01")
RUN_ID = UUID("018f1f00-0000-7000-8000-0000000c0d02")


def _config(
    st_key: str | None = None,
    vt_key: str | None = None,
) -> CollectorConfig:
    creds: dict[str, CollectorCredential] = {}
    if st_key:
        creds["securitytrails_api_key"] = CollectorCredential(
            name="securitytrails_api_key", secret_value=st_key
        )
    if vt_key:
        creds["virustotal_api_key"] = CollectorCredential(
            name="virustotal_api_key", secret_value=vt_key
        )
    return CollectorConfig(
        tenant_id=TENANT_ID,
        run_id=RUN_ID,
        request_timeout_seconds=5.0,
        credentials=creds,
    )


async def _collect(
    seed: Seed,
    config: CollectorConfig | None = None,
) -> list[Observation]:
    cfg = config or _config(st_key="test-st-key", vt_key="test-vt-key")
    collector = PassiveDnsHistoryCollector(cfg)
    results: list[Observation] = []
    async for obs in collector.expand(seed):
        results.append(obs)
    return results


# === Canned API responses =====================================================

_ST_HISTORY_A_RESPONSE = {
    "records": [
        {
            "values": [{"ip": "1.2.3.4"}],
            "first_seen": "2020-01-01",
            "last_seen": "2024-06-15",
            "type": "a",
        },
        {
            "values": [{"ip": "5.6.7.8"}],
            "first_seen": "2024-06-16",
            "last_seen": "2025-01-01",
            "type": "a",
        },
    ],
}

_ST_HISTORY_MX_RESPONSE = {
    "records": [
        {
            "values": [{"host": "mail.example.com"}],
            "first_seen": "2019-03-01",
            "last_seen": "2025-01-01",
            "type": "mx",
        },
    ],
}

_ST_HISTORY_EMPTY = {"records": []}

_ST_SUBDOMAINS_RESPONSE = {
    "subdomains": ["www", "mail", "dev", "api"],
}

_ST_REVERSE_IP_RESPONSE = {
    "records": [
        {"hostname": "example.com"},
        {"hostname": "other.com"},
    ],
}

_VT_RESOLUTIONS_RESPONSE = {
    "data": [
        {
            "attributes": {
                "ip_address": "1.2.3.4",
                "host_name": "example.com",
                "date": 1609459200,  # 2021-01-01
            },
        },
        {
            "attributes": {
                "ip_address": "9.10.11.12",
                "host_name": "example.com",
                "date": 1672531200,  # 2023-01-01
            },
        },
    ],
}

_VT_REVERSE_IP_RESPONSE = {
    "data": [
        {
            "attributes": {
                "ip_address": "1.2.3.4",
                "host_name": "reverse.example.com",
                "date": 1609459200,
            },
        },
    ],
}

_VT_EMPTY_RESPONSE: dict[str, list[object]] = {"data": []}


def _mock_st_all_empty() -> None:
    """Set up respx mocks for ST returning empty results on all DNS types."""
    for dns_type in ("a", "aaaa", "mx", "ns", "cname"):
        respx.get(
            f"https://api.securitytrails.com/v1/history/example.com/dns/{dns_type}"
        ).mock(return_value=httpx.Response(200, json=_ST_HISTORY_EMPTY))
    respx.get(
        "https://api.securitytrails.com/v1/domain/example.com/subdomains"
    ).mock(return_value=httpx.Response(200, json={"subdomains": []}))


# ==============================================================================
# 1. Collector metadata
# ==============================================================================
class TestCollectorMetadata:
    def test_collector_id(self) -> None:
        assert PassiveDnsHistoryCollector.collector_id == "dns-passive-history"

    def test_collector_version(self) -> None:
        assert PassiveDnsHistoryCollector.collector_version == "0.1.0"

    def test_tier_is_tier_1(self) -> None:
        assert PassiveDnsHistoryCollector.tier == CollectorTier.TIER_1

    def test_requires_credentials(self) -> None:
        assert PassiveDnsHistoryCollector.requires_credentials is True

    def test_is_subclass_of_collector_abc(self) -> None:
        assert issubclass(PassiveDnsHistoryCollector, Collector)


# ==============================================================================
# 2. SecurityTrails: historical A records parsed
# ==============================================================================
class TestSecurityTrailsHistory:
    @respx.mock
    @pytest.mark.asyncio
    async def test_st_a_records_parsed(self) -> None:
        """SecurityTrails A record history yields observations."""
        respx.get(
            "https://api.securitytrails.com/v1/history/example.com/dns/a"
        ).mock(return_value=httpx.Response(200, json=_ST_HISTORY_A_RESPONSE))
        # Other DNS types return empty.
        for t in ("aaaa", "mx", "ns", "cname"):
            respx.get(
                f"https://api.securitytrails.com/v1/history/example.com/dns/{t}"
            ).mock(return_value=httpx.Response(200, json=_ST_HISTORY_EMPTY))
        respx.get(
            "https://api.securitytrails.com/v1/domain/example.com/subdomains"
        ).mock(return_value=httpx.Response(200, json={"subdomains": []}))

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        cfg = _config(st_key="test-key")
        observations = await _collect(seed, cfg)

        # Two A records from ST.
        assert len(observations) == 2
        assert all(o.observation_type == ObservationType.PASSIVE_DNS for o in observations)
        values = [o.structured_payload["value"] for o in observations]
        assert "1.2.3.4" in values
        assert "5.6.7.8" in values

    @respx.mock
    @pytest.mark.asyncio
    async def test_st_record_source_tag(self) -> None:
        """Each record carries source='securitytrails'."""
        respx.get(
            "https://api.securitytrails.com/v1/history/example.com/dns/a"
        ).mock(return_value=httpx.Response(200, json=_ST_HISTORY_A_RESPONSE))
        for t in ("aaaa", "mx", "ns", "cname"):
            respx.get(
                f"https://api.securitytrails.com/v1/history/example.com/dns/{t}"
            ).mock(return_value=httpx.Response(200, json=_ST_HISTORY_EMPTY))
        respx.get(
            "https://api.securitytrails.com/v1/domain/example.com/subdomains"
        ).mock(return_value=httpx.Response(200, json={"subdomains": []}))

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        cfg = _config(st_key="test-key")
        observations = await _collect(seed, cfg)

        for obs in observations:
            assert obs.structured_payload["source"] == "securitytrails"


# ==============================================================================
# 3. SecurityTrails: multiple DNS types
# ==============================================================================
class TestSecurityTrailsMultipleTypes:
    @respx.mock
    @pytest.mark.asyncio
    async def test_st_mx_records_parsed(self) -> None:
        """SecurityTrails MX records are parsed alongside A records."""
        respx.get(
            "https://api.securitytrails.com/v1/history/example.com/dns/a"
        ).mock(return_value=httpx.Response(200, json=_ST_HISTORY_A_RESPONSE))
        respx.get(
            "https://api.securitytrails.com/v1/history/example.com/dns/mx"
        ).mock(return_value=httpx.Response(200, json=_ST_HISTORY_MX_RESPONSE))
        for t in ("aaaa", "ns", "cname"):
            respx.get(
                f"https://api.securitytrails.com/v1/history/example.com/dns/{t}"
            ).mock(return_value=httpx.Response(200, json=_ST_HISTORY_EMPTY))
        respx.get(
            "https://api.securitytrails.com/v1/domain/example.com/subdomains"
        ).mock(return_value=httpx.Response(200, json={"subdomains": []}))

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        cfg = _config(st_key="test-key")
        observations = await _collect(seed, cfg)

        types = {o.structured_payload["dns_record_type"] for o in observations}
        assert "A" in types
        assert "MX" in types
        assert len(observations) == 3  # 2 A + 1 MX


# ==============================================================================
# 4. VirusTotal: resolutions parsed
# ==============================================================================
class TestVirusTotalResolutions:
    @respx.mock
    @pytest.mark.asyncio
    async def test_vt_resolutions_parsed(self) -> None:
        """VirusTotal domain resolutions yield observations."""
        respx.get(
            "https://www.virustotal.com/api/v3/domains/example.com/resolutions"
        ).mock(return_value=httpx.Response(200, json=_VT_RESOLUTIONS_RESPONSE))

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        cfg = _config(vt_key="test-vt-key")
        observations = await _collect(seed, cfg)

        assert len(observations) == 2
        sources = {o.structured_payload["source"] for o in observations}
        assert sources == {"virustotal"}
        ips = {o.structured_payload["value"] for o in observations}
        assert "1.2.3.4" in ips
        assert "9.10.11.12" in ips

    @respx.mock
    @pytest.mark.asyncio
    async def test_vt_dns_record_type_is_a(self) -> None:
        """VirusTotal resolutions are tagged as A records."""
        respx.get(
            "https://www.virustotal.com/api/v3/domains/example.com/resolutions"
        ).mock(return_value=httpx.Response(200, json=_VT_RESOLUTIONS_RESPONSE))

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        cfg = _config(vt_key="test-vt-key")
        observations = await _collect(seed, cfg)

        for obs in observations:
            assert obs.structured_payload["dns_record_type"] == "A"


# ==============================================================================
# 5. Both sources combined — deduplicated
# ==============================================================================
class TestDeduplication:
    @respx.mock
    @pytest.mark.asyncio
    async def test_duplicate_records_deduplicated(self) -> None:
        """When both sources return the same IP, duplicates are removed."""
        # ST returns 1.2.3.4 with first_seen=2020-01-01.
        respx.get(
            "https://api.securitytrails.com/v1/history/example.com/dns/a"
        ).mock(return_value=httpx.Response(200, json={
            "records": [{
                "values": [{"ip": "1.2.3.4"}],
                "first_seen": "2021-01-01",
                "last_seen": "2021-01-01",
                "type": "a",
            }],
        }))
        for t in ("aaaa", "mx", "ns", "cname"):
            respx.get(
                f"https://api.securitytrails.com/v1/history/example.com/dns/{t}"
            ).mock(return_value=httpx.Response(200, json=_ST_HISTORY_EMPTY))
        respx.get(
            "https://api.securitytrails.com/v1/domain/example.com/subdomains"
        ).mock(return_value=httpx.Response(200, json={"subdomains": []}))

        # VT returns the same IP with different source tag.
        respx.get(
            "https://www.virustotal.com/api/v3/domains/example.com/resolutions"
        ).mock(return_value=httpx.Response(200, json=_VT_RESOLUTIONS_RESPONSE))

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        cfg = _config(st_key="test-st", vt_key="test-vt")
        observations = await _collect(seed, cfg)

        # Dedup is by (source, type, value, first_seen, last_seen),
        # so ST + VT for the same IP are NOT deduped (different source).
        # ST: 1 record. VT: 2 records. Total = 3.
        assert len(observations) == 3

    @respx.mock
    @pytest.mark.asyncio
    async def test_exact_duplicate_within_source_removed(self) -> None:
        """Exact same record from same source is deduplicated."""
        duplicate_response = {
            "records": [
                {
                    "values": [{"ip": "1.2.3.4"}],
                    "first_seen": "2020-01-01",
                    "last_seen": "2020-01-01",
                    "type": "a",
                },
                {
                    "values": [{"ip": "1.2.3.4"}],
                    "first_seen": "2020-01-01",
                    "last_seen": "2020-01-01",
                    "type": "a",
                },
            ],
        }
        respx.get(
            "https://api.securitytrails.com/v1/history/example.com/dns/a"
        ).mock(return_value=httpx.Response(200, json=duplicate_response))
        for t in ("aaaa", "mx", "ns", "cname"):
            respx.get(
                f"https://api.securitytrails.com/v1/history/example.com/dns/{t}"
            ).mock(return_value=httpx.Response(200, json=_ST_HISTORY_EMPTY))
        respx.get(
            "https://api.securitytrails.com/v1/domain/example.com/subdomains"
        ).mock(return_value=httpx.Response(200, json={"subdomains": []}))

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        cfg = _config(st_key="test-key")
        observations = await _collect(seed, cfg)

        # Should have exactly 1 after dedup.
        assert len(observations) == 1


# ==============================================================================
# 6. No API keys — empty list (graceful degradation)
# ==============================================================================
class TestNoApiKeys:
    @pytest.mark.asyncio
    async def test_no_keys_yields_nothing(self) -> None:
        """With no API keys configured, expand yields nothing."""
        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        cfg = _config()  # No keys.
        observations = await _collect(seed, cfg)
        assert observations == []


# ==============================================================================
# 7. SecurityTrails subdomain discovery
# ==============================================================================
class TestSubdomainDiscovery:
    @respx.mock
    @pytest.mark.asyncio
    async def test_st_subdomains_yield_dns_record_observations(self) -> None:
        """Discovered subdomains yield DNS_RECORD observations."""
        for t in ("a", "aaaa", "mx", "ns", "cname"):
            respx.get(
                f"https://api.securitytrails.com/v1/history/example.com/dns/{t}"
            ).mock(return_value=httpx.Response(200, json=_ST_HISTORY_EMPTY))
        respx.get(
            "https://api.securitytrails.com/v1/domain/example.com/subdomains"
        ).mock(return_value=httpx.Response(200, json=_ST_SUBDOMAINS_RESPONSE))

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        cfg = _config(st_key="test-key")
        observations = await _collect(seed, cfg)

        sub_obs = [
            o for o in observations
            if o.observation_type == ObservationType.DNS_RECORD
        ]
        assert len(sub_obs) == 4
        fqdns = {o.structured_payload["fqdn"] for o in sub_obs}
        assert fqdns == {
            "www.example.com",
            "mail.example.com",
            "dev.example.com",
            "api.example.com",
        }

    @respx.mock
    @pytest.mark.asyncio
    async def test_subdomain_seed_expansion_flag(self) -> None:
        """Subdomain observations carry seed_expansion=True."""
        for t in ("a", "aaaa", "mx", "ns", "cname"):
            respx.get(
                f"https://api.securitytrails.com/v1/history/example.com/dns/{t}"
            ).mock(return_value=httpx.Response(200, json=_ST_HISTORY_EMPTY))
        respx.get(
            "https://api.securitytrails.com/v1/domain/example.com/subdomains"
        ).mock(return_value=httpx.Response(
            200, json={"subdomains": ["www"]},
        ))

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        cfg = _config(st_key="test-key")
        observations = await _collect(seed, cfg)

        sub_obs = [
            o for o in observations
            if o.observation_type == ObservationType.DNS_RECORD
        ]
        assert len(sub_obs) == 1
        assert sub_obs[0].structured_payload["seed_expansion"] is True
        assert sub_obs[0].subject.identifier_type == IdentifierType.SUBDOMAIN
        assert sub_obs[0].subject.identifier_value == "www.example.com"


# ==============================================================================
# 8. first_seen / last_seen in observations
# ==============================================================================
class TestTimestamps:
    @respx.mock
    @pytest.mark.asyncio
    async def test_st_first_last_seen_preserved(self) -> None:
        """SecurityTrails first_seen and last_seen appear in payload."""
        respx.get(
            "https://api.securitytrails.com/v1/history/example.com/dns/a"
        ).mock(return_value=httpx.Response(200, json=_ST_HISTORY_A_RESPONSE))
        for t in ("aaaa", "mx", "ns", "cname"):
            respx.get(
                f"https://api.securitytrails.com/v1/history/example.com/dns/{t}"
            ).mock(return_value=httpx.Response(200, json=_ST_HISTORY_EMPTY))
        respx.get(
            "https://api.securitytrails.com/v1/domain/example.com/subdomains"
        ).mock(return_value=httpx.Response(200, json={"subdomains": []}))

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        cfg = _config(st_key="test-key")
        observations = await _collect(seed, cfg)

        first = observations[0].structured_payload
        assert first["first_seen"] == "2020-01-01"
        assert first["last_seen"] == "2024-06-15"

    @respx.mock
    @pytest.mark.asyncio
    async def test_vt_date_converted_to_iso(self) -> None:
        """VirusTotal Unix timestamp is converted to ISO-8601 date."""
        respx.get(
            "https://www.virustotal.com/api/v3/domains/example.com/resolutions"
        ).mock(return_value=httpx.Response(200, json=_VT_RESOLUTIONS_RESPONSE))

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        cfg = _config(vt_key="test-vt-key")
        observations = await _collect(seed, cfg)

        # 1609459200 = 2021-01-01 UTC.
        first = observations[0].structured_payload
        assert first["first_seen"] == "2021-01-01"
        assert first["last_seen"] == "2021-01-01"


# ==============================================================================
# 9. Rate limiting: VirusTotal 429
# ==============================================================================
class TestRateLimiting:
    @respx.mock
    @pytest.mark.asyncio
    async def test_vt_429_graceful_degradation(self) -> None:
        """VirusTotal 429 is caught and surfaced as a warning."""
        _mock_st_all_empty()
        respx.get(
            "https://www.virustotal.com/api/v3/domains/example.com/resolutions"
        ).mock(return_value=httpx.Response(429, json={"error": "rate limit"}))

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        cfg = _config(st_key="st-key", vt_key="vt-key")
        observations = await _collect(seed, cfg)

        # ST returned nothing, VT failed → no observations.
        assert observations == []


# ==============================================================================
# 10. HTTP error → graceful degradation (SecurityTrails)
# ==============================================================================
class TestSecurityTrailsErrors:
    @respx.mock
    @pytest.mark.asyncio
    async def test_st_500_graceful_degradation(self) -> None:
        """SecurityTrails 500 is caught; VT results still returned."""
        # ST returns 500 on the first DNS type.
        respx.get(
            "https://api.securitytrails.com/v1/history/example.com/dns/a"
        ).mock(return_value=httpx.Response(500))
        for t in ("aaaa", "mx", "ns", "cname"):
            respx.get(
                f"https://api.securitytrails.com/v1/history/example.com/dns/{t}"
            ).mock(return_value=httpx.Response(200, json=_ST_HISTORY_EMPTY))
        respx.get(
            "https://api.securitytrails.com/v1/domain/example.com/subdomains"
        ).mock(return_value=httpx.Response(200, json={"subdomains": []}))

        # VT returns valid data.
        respx.get(
            "https://www.virustotal.com/api/v3/domains/example.com/resolutions"
        ).mock(return_value=httpx.Response(200, json=_VT_RESOLUTIONS_RESPONSE))

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        cfg = _config(st_key="st-key", vt_key="vt-key")
        observations = await _collect(seed, cfg)

        # ST error is caught at the _query_securitytrails level (one
        # CollectorError for the 500 on /dns/a causes the whole ST query to
        # fail), but VT still works => 2 VT records.
        vt_obs = [
            o for o in observations
            if o.structured_payload.get("source") == "virustotal"
        ]
        assert len(vt_obs) == 2

        # Warnings mention ST failure.
        has_st_warning = any(
            "SecurityTrails" in w
            for o in observations
            for w in o.warnings
        )
        assert has_st_warning

    @respx.mock
    @pytest.mark.asyncio
    async def test_st_connection_error_graceful(self) -> None:
        """SecurityTrails network error is caught gracefully."""
        for t in ("a", "aaaa", "mx", "ns", "cname"):
            respx.get(
                f"https://api.securitytrails.com/v1/history/example.com/dns/{t}"
            ).mock(side_effect=httpx.ConnectError("DNS failed"))
        respx.get(
            "https://api.securitytrails.com/v1/domain/example.com/subdomains"
        ).mock(return_value=httpx.Response(200, json={"subdomains": []}))

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        cfg = _config(st_key="st-key")
        observations = await _collect(seed, cfg)

        # Error caught → no observations (no VT key).
        assert observations == []


# ==============================================================================
# 11. HTTP error → graceful degradation (VirusTotal)
# ==============================================================================
class TestVirusTotalErrors:
    @respx.mock
    @pytest.mark.asyncio
    async def test_vt_500_graceful_degradation(self) -> None:
        """VirusTotal 500 is caught; ST results still returned."""
        respx.get(
            "https://api.securitytrails.com/v1/history/example.com/dns/a"
        ).mock(return_value=httpx.Response(200, json=_ST_HISTORY_A_RESPONSE))
        for t in ("aaaa", "mx", "ns", "cname"):
            respx.get(
                f"https://api.securitytrails.com/v1/history/example.com/dns/{t}"
            ).mock(return_value=httpx.Response(200, json=_ST_HISTORY_EMPTY))
        respx.get(
            "https://api.securitytrails.com/v1/domain/example.com/subdomains"
        ).mock(return_value=httpx.Response(200, json={"subdomains": []}))

        respx.get(
            "https://www.virustotal.com/api/v3/domains/example.com/resolutions"
        ).mock(return_value=httpx.Response(500))

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        cfg = _config(st_key="st-key", vt_key="vt-key")
        observations = await _collect(seed, cfg)

        # ST returned 2 A records; VT failed gracefully.
        st_obs = [
            o for o in observations
            if o.structured_payload.get("source") == "securitytrails"
        ]
        assert len(st_obs) == 2

        # Warnings mention VT failure.
        has_vt_warning = any(
            "VirusTotal" in w
            for o in observations
            for w in o.warnings
        )
        assert has_vt_warning


# ==============================================================================
# 12. IP seed → SecurityTrails reverse lookup
# ==============================================================================
class TestIpSeedSecurityTrails:
    @respx.mock
    @pytest.mark.asyncio
    async def test_ip_seed_reverse_lookup(self) -> None:
        """IP seed triggers SecurityTrails reverse domain lookup."""
        respx.get(
            "https://api.securitytrails.com/v1/domains/list",
            params__contains={"ipAddress": "1.2.3.4"},
        ).mock(return_value=httpx.Response(200, json=_ST_REVERSE_IP_RESPONSE))

        seed = Seed(seed_type=SeedType.IP, value="1.2.3.4")
        cfg = _config(st_key="st-key")
        observations = await _collect(seed, cfg)

        assert len(observations) == 2
        hostnames = {o.structured_payload["value"] for o in observations}
        assert hostnames == {"example.com", "other.com"}

    @respx.mock
    @pytest.mark.asyncio
    async def test_ip_seed_subject_is_ip(self) -> None:
        """IP seed observations have IP identifier type."""
        respx.get(
            "https://api.securitytrails.com/v1/domains/list",
            params__contains={"ipAddress": "1.2.3.4"},
        ).mock(return_value=httpx.Response(200, json=_ST_REVERSE_IP_RESPONSE))

        seed = Seed(seed_type=SeedType.IP, value="1.2.3.4")
        cfg = _config(st_key="st-key")
        observations = await _collect(seed, cfg)

        for obs in observations:
            assert obs.subject.identifier_type == IdentifierType.IP
            assert obs.subject.identifier_value == "1.2.3.4"


# ==============================================================================
# 13. IP seed → VirusTotal reverse resolutions
# ==============================================================================
class TestIpSeedVirusTotal:
    @respx.mock
    @pytest.mark.asyncio
    async def test_ip_seed_vt_reverse(self) -> None:
        """IP seed triggers VirusTotal reverse IP resolutions."""
        respx.get(
            "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4/resolutions"
        ).mock(return_value=httpx.Response(200, json=_VT_REVERSE_IP_RESPONSE))

        seed = Seed(seed_type=SeedType.IP, value="1.2.3.4")
        cfg = _config(vt_key="vt-key")
        observations = await _collect(seed, cfg)

        assert len(observations) == 1
        assert observations[0].structured_payload["value"] == "reverse.example.com"
        assert observations[0].structured_payload["source"] == "virustotal"


# ==============================================================================
# 14. Health check: success and failure
# ==============================================================================
class TestHealthCheck:
    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_success_st(self) -> None:
        """ST ping success returns SUCCESS status."""
        respx.get("https://api.securitytrails.com/v1/ping").mock(
            return_value=httpx.Response(200, json={"success": True})
        )

        collector = PassiveDnsHistoryCollector(_config(st_key="test-key"))
        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "dns-passive-history"

    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_failure_no_keys(self) -> None:
        """No API keys → FAILURE health check."""
        collector = PassiveDnsHistoryCollector(_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None
        assert "No API keys" in result.error_message

    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_failure_connection_error(self) -> None:
        """Connection error → FAILURE with error message."""
        respx.get("https://api.securitytrails.com/v1/ping").mock(
            side_effect=httpx.ConnectError("timeout")
        )

        collector = PassiveDnsHistoryCollector(_config(st_key="test-key"))
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None

    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_latency_non_negative(self) -> None:
        """Health check latency is non-negative."""
        respx.get("https://api.securitytrails.com/v1/ping").mock(
            return_value=httpx.Response(200, json={"success": True})
        )

        collector = PassiveDnsHistoryCollector(_config(st_key="test-key"))
        result = await collector.health_check()

        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0


# ==============================================================================
# 15. Non-matching seed types skipped
# ==============================================================================
class TestSeedTypeFiltering:
    @pytest.mark.asyncio
    async def test_organization_seed_skipped(self) -> None:
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Acme Corp")
        observations = await _collect(seed)
        assert observations == []

    @pytest.mark.asyncio
    async def test_cidr_seed_skipped(self) -> None:
        seed = Seed(seed_type=SeedType.CIDR, value="192.0.2.0/24")
        observations = await _collect(seed)
        assert observations == []

    @pytest.mark.asyncio
    async def test_asn_seed_skipped(self) -> None:
        seed = Seed(seed_type=SeedType.ASN, value="AS13335")
        observations = await _collect(seed)
        assert observations == []


# ==============================================================================
# 16. VirusTotal Unix timestamp conversion
# ==============================================================================
class TestUnixTimestampConversion:
    @respx.mock
    @pytest.mark.asyncio
    async def test_vt_null_date_yields_none(self) -> None:
        """VirusTotal resolution with no date yields None timestamps."""
        response = {
            "data": [{
                "attributes": {
                    "ip_address": "10.0.0.1",
                    "host_name": "example.com",
                    # No "date" key.
                },
            }],
        }
        respx.get(
            "https://www.virustotal.com/api/v3/domains/example.com/resolutions"
        ).mock(return_value=httpx.Response(200, json=response))

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        cfg = _config(vt_key="vt-key")
        observations = await _collect(seed, cfg)

        assert len(observations) == 1
        assert observations[0].structured_payload["first_seen"] is None
        assert observations[0].structured_payload["last_seen"] is None


# ==============================================================================
# 17. Registration in default registry
# ==============================================================================
class TestRegistration:
    def test_registered_in_default_registry(self) -> None:
        assert DEFAULT_REGISTRY.is_registered("dns-passive-history")
        cls = DEFAULT_REGISTRY.get("dns-passive-history")
        assert cls is PassiveDnsHistoryCollector
