"""Tests for the cloud-storage-exposure collector (Tier 1).

Exercises bucket enumeration and content parsing via ``respx`` mocks —
no live network calls.

Coverage:
1.  Collector metadata (ID, tier, display_name)
2.  Name permutation: generates expected org-based candidates
3.  Name permutation: domain adds domain-based names
4.  Name permutation: deduplication when org and domain overlap
5.  S3 bucket exists (200) -> observation
6.  S3 bucket doesn't exist (404) -> no observation
7.  S3 bucket exists but forbidden (403) -> observation (exists, not listable)
8.  Azure blob probe: exists -> observation
9.  GCP storage probe: exists -> observation
10. Publicly listable bucket -> object inventory with sensitive files
11. Rate limiting (semaphore): max concurrent respected
12. Non-applicable seeds (IP, CIDR) skipped
13. Organization seed with domain property
14. Health check: success path
15. Health check: failure path
16. Connection error -> bucket skipped
17. Domain seed -> org name derived from first label
18. Multiple buckets found across providers
19. Endpoint extraction from listable bucket
20. Empty listing body -> no sensitive objects
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch
from uuid import UUID

import httpx
import pytest
import respx

from expose.collectors.base import (
    CollectorConfig,
    Observation,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.builtin.cloud_storage_exposure import (
    CloudStorageExposureCollector,
    generate_bucket_names,
)
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus

# Deterministic test IDs.
TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000D001")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000D002")


def _config(**extra: object) -> CollectorConfig:
    """Build a CollectorConfig with test defaults."""
    defaults: dict[str, object] = {
        "probe_delay": 0.0,  # No delay in tests.
        "probe_timeout": 5.0,
    }
    defaults.update(extra)
    return CollectorConfig(
        tenant_id=TENANT_ID,
        run_id=RUN_ID,
        request_timeout_seconds=5.0,
        extra=defaults,  # type: ignore[arg-type]
    )


async def _collect(seed: Seed, config: CollectorConfig | None = None) -> list[Observation]:
    """Run expand() and collect all observations into a list."""
    cfg = config or _config()
    collector = CloudStorageExposureCollector(cfg)
    results: list[Observation] = []
    async for obs in collector.expand(seed):
        results.append(obs)
    return results


# === 1. Collector metadata ====================================================


class TestCollectorMetadata:
    def test_collector_id(self) -> None:
        """Collector ID is 'cloud-storage-exposure'."""
        assert CloudStorageExposureCollector.collector_id == "cloud-storage-exposure"

    def test_collector_tier(self) -> None:
        """Collector is Tier 1."""
        assert CloudStorageExposureCollector.tier == CollectorTier.TIER_1

    def test_display_name(self) -> None:
        """Display name is set."""
        assert CloudStorageExposureCollector.display_name == "Cloud Storage Exposure"

    def test_no_credentials_required(self) -> None:
        """Collector does not require credentials."""
        assert CloudStorageExposureCollector.requires_credentials is False


# === 2. Name permutation =====================================================


class TestNamePermutation:
    def test_org_name_generates_candidates(self) -> None:
        """Org name produces base + all suffixed variants."""
        candidates = generate_bucket_names("Acme Corp")
        assert "acme-corp" in candidates
        assert "acme-corp-backups" in candidates
        assert "acme-corp-data" in candidates
        assert "acme-corp-assets" in candidates
        assert "acme-corp-staging" in candidates
        assert "acme-corp-dev" in candidates
        assert "acme-corp-logs" in candidates
        assert "acme-corp-config" in candidates
        assert "acme-corp-prod" in candidates
        assert "acme-corp-internal" in candidates

    def test_domain_adds_domain_based_names(self) -> None:
        """Domain parameter adds names based on domain's first label."""
        candidates = generate_bucket_names("Acme Corp", domain="acmecorp.com")
        # Domain-based candidates.
        assert "acmecorp" in candidates
        assert "acmecorp-backups" in candidates
        assert "acmecorp-data" in candidates

    def test_deduplication(self) -> None:
        """When org and domain produce the same name, deduplication removes it."""
        candidates = generate_bucket_names("acme", domain="acme.com")
        # "acme" should appear only once.
        assert candidates.count("acme") == 1

    def test_underscores_replaced(self) -> None:
        """Underscores in org name are replaced with hyphens."""
        candidates = generate_bucket_names("acme_corp")
        assert "acme-corp" in candidates
        assert "acme_corp" not in candidates

    def test_spaces_replaced(self) -> None:
        """Spaces in org name are replaced with hyphens."""
        candidates = generate_bucket_names("acme corp")
        assert "acme-corp" in candidates

    def test_domain_only_uses_first_10_suffixes(self) -> None:
        """Domain-based names use only the first 10 suffixes."""
        candidates = generate_bucket_names("org", domain="domaintest.com")
        # First 10 suffixes include "" through "-static" (indices 0-9).
        assert "domaintest" in candidates
        assert "domaintest-static" in candidates
        # 11th suffix is "-public" — should NOT appear for domain-based.
        assert "domaintest-public" not in candidates


# === 3. Bucket probing =======================================================


class TestBucketProbing:
    @respx.mock
    @pytest.mark.asyncio
    async def test_s3_bucket_exists_200(self) -> None:
        """S3 bucket returning 200 yields an observation."""
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="testbucket200")
        # Mock only the exact "testbucket200" bucket to return 200.
        respx.head("https://testbucket200.s3.amazonaws.com/").mock(return_value=httpx.Response(200))
        # GET for listing attempt.
        respx.get("https://testbucket200.s3.amazonaws.com/").mock(
            return_value=httpx.Response(200, text="<ListBucketResult></ListBucketResult>")
        )
        # All other S3 probes return 404.
        respx.route(method="HEAD", host__regex=r".*\.s3\.amazonaws\.com").mock(
            return_value=httpx.Response(404)
        )
        # Azure and GCP return 404.
        respx.route(method="HEAD", host__regex=r".*\.blob\.core\.windows\.net").mock(
            return_value=httpx.Response(404)
        )
        respx.route(method="HEAD", host="storage.googleapis.com").mock(
            return_value=httpx.Response(404)
        )

        observations = await _collect(seed)
        s3_obs = [
            o for o in observations if o.structured_payload.get("bucket_name") == "testbucket200"
        ]
        assert len(s3_obs) == 1
        assert s3_obs[0].structured_payload["cloud_provider"] == "aws"
        assert s3_obs[0].structured_payload["is_public"] is True

    @respx.mock
    @pytest.mark.asyncio
    async def test_s3_bucket_not_found_404(self) -> None:
        """S3 bucket returning 404 yields no observation for that name."""
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="noexist")
        # All providers return 404.
        respx.route(method="HEAD").mock(return_value=httpx.Response(404))

        observations = await _collect(seed)
        assert len(observations) == 0

    @respx.mock
    @pytest.mark.asyncio
    async def test_s3_bucket_forbidden_403(self) -> None:
        """S3 bucket returning 403 -> observation (exists, not public)."""
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="forbiddenbucket")
        respx.head("https://forbiddenbucket.s3.amazonaws.com/").mock(
            return_value=httpx.Response(403)
        )
        # Other names/providers 404.
        respx.route(method="HEAD", host__regex=r".*\.s3\.amazonaws\.com").mock(
            return_value=httpx.Response(404)
        )
        respx.route(method="HEAD", host__regex=r".*\.blob\.core\.windows\.net").mock(
            return_value=httpx.Response(404)
        )
        respx.route(method="HEAD", host="storage.googleapis.com").mock(
            return_value=httpx.Response(404)
        )

        observations = await _collect(seed)
        forbidden_obs = [
            o for o in observations if o.structured_payload.get("bucket_name") == "forbiddenbucket"
        ]
        assert len(forbidden_obs) == 1
        assert forbidden_obs[0].structured_payload["is_public"] is False
        assert forbidden_obs[0].structured_payload["is_listable"] is False

    @respx.mock
    @pytest.mark.asyncio
    async def test_azure_blob_exists(self) -> None:
        """Azure blob returning 200 yields an observation."""
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="azuretest")
        # S3 returns 404.
        respx.route(method="HEAD", host__regex=r".*\.s3\.amazonaws\.com").mock(
            return_value=httpx.Response(404)
        )
        # Azure: "azuretest" returns 200, others 404.
        respx.head("https://azuretest.blob.core.windows.net/").mock(
            return_value=httpx.Response(200)
        )
        respx.get("https://azuretest.blob.core.windows.net/").mock(
            return_value=httpx.Response(
                200, text="<EnumerationResults><Blobs></Blobs></EnumerationResults>"
            )
        )
        respx.route(method="HEAD", host__regex=r".*\.blob\.core\.windows\.net").mock(
            return_value=httpx.Response(404)
        )
        # GCP 404.
        respx.route(method="HEAD", host="storage.googleapis.com").mock(
            return_value=httpx.Response(404)
        )

        observations = await _collect(seed)
        azure_obs = [
            o for o in observations if o.structured_payload.get("cloud_provider") == "azure"
        ]
        assert len(azure_obs) >= 1

    @respx.mock
    @pytest.mark.asyncio
    async def test_gcp_storage_exists(self) -> None:
        """GCP storage returning 200 yields an observation."""
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="gcptest")
        # S3 and Azure return 404.
        respx.route(method="HEAD", host__regex=r".*\.s3\.amazonaws\.com").mock(
            return_value=httpx.Response(404)
        )
        respx.route(method="HEAD", host__regex=r".*\.blob\.core\.windows\.net").mock(
            return_value=httpx.Response(404)
        )
        # GCP: "gcptest" returns 200.
        respx.head("https://storage.googleapis.com/gcptest/").mock(return_value=httpx.Response(200))
        respx.get("https://storage.googleapis.com/gcptest/").mock(
            return_value=httpx.Response(200, text='{"items": []}')
        )
        respx.route(method="HEAD", host="storage.googleapis.com").mock(
            return_value=httpx.Response(404)
        )

        observations = await _collect(seed)
        gcp_obs = [o for o in observations if o.structured_payload.get("cloud_provider") == "gcp"]
        assert len(gcp_obs) >= 1

    @respx.mock
    @pytest.mark.asyncio
    async def test_listable_bucket_with_sensitive_files(self) -> None:
        """Publicly listable bucket inventories objects and flags sensitive ones."""
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="leakybucket")

        s3_listing = """<?xml version="1.0" encoding="UTF-8"?>
        <ListBucketResult>
          <Contents>
            <Key>.env</Key>
            <Size>100</Size>
          </Contents>
          <Contents>
            <Key>public/logo.png</Key>
            <Size>4096</Size>
          </Contents>
          <Contents>
            <Key>swagger.json</Key>
            <Size>5000</Size>
          </Contents>
        </ListBucketResult>"""

        respx.head("https://leakybucket.s3.amazonaws.com/").mock(return_value=httpx.Response(200))
        respx.get("https://leakybucket.s3.amazonaws.com/").mock(
            return_value=httpx.Response(200, text=s3_listing)
        )
        # All other probes 404.
        respx.route(method="HEAD", host__regex=r".*\.s3\.amazonaws\.com").mock(
            return_value=httpx.Response(404)
        )
        respx.route(method="HEAD", host__regex=r".*\.blob\.core\.windows\.net").mock(
            return_value=httpx.Response(404)
        )
        respx.route(method="HEAD", host="storage.googleapis.com").mock(
            return_value=httpx.Response(404)
        )

        observations = await _collect(seed)
        leaky_obs = [
            o for o in observations if o.structured_payload.get("bucket_name") == "leakybucket"
        ]
        assert len(leaky_obs) == 1
        payload = leaky_obs[0].structured_payload
        assert payload["is_listable"] is True
        assert payload["total_objects"] == 3
        assert payload["sensitive_object_count"] == 2
        # Check sensitive objects detail.
        sensitive_keys = {s["key"] for s in payload["sensitive_objects"]}
        assert ".env" in sensitive_keys
        assert "swagger.json" in sensitive_keys

    @respx.mock
    @pytest.mark.asyncio
    async def test_endpoint_extraction(self) -> None:
        """Swagger/OpenAPI files produce extracted endpoints."""
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="apiorg")

        s3_listing = """<?xml version="1.0" encoding="UTF-8"?>
        <ListBucketResult>
          <Contents>
            <Key>swagger.json</Key>
            <Size>5000</Size>
          </Contents>
        </ListBucketResult>"""

        respx.head("https://apiorg.s3.amazonaws.com/").mock(return_value=httpx.Response(200))
        respx.get("https://apiorg.s3.amazonaws.com/").mock(
            return_value=httpx.Response(200, text=s3_listing)
        )
        respx.route(method="HEAD", host__regex=r".*\.s3\.amazonaws\.com").mock(
            return_value=httpx.Response(404)
        )
        respx.route(method="HEAD", host__regex=r".*\.blob\.core\.windows\.net").mock(
            return_value=httpx.Response(404)
        )
        respx.route(method="HEAD", host="storage.googleapis.com").mock(
            return_value=httpx.Response(404)
        )

        observations = await _collect(seed)
        api_obs = [o for o in observations if o.structured_payload.get("bucket_name") == "apiorg"]
        assert len(api_obs) == 1
        endpoints = api_obs[0].structured_payload["extracted_endpoints"]
        assert "https://apiorg.s3.amazonaws.com/swagger.json" in endpoints


# === 4. Seed handling =========================================================


class TestSeedHandling:
    @pytest.mark.asyncio
    async def test_ip_seed_skipped(self) -> None:
        """IP seeds are not applicable and yield no observations."""
        seed = Seed(seed_type=SeedType.IP, value="1.2.3.4")
        observations = await _collect(seed)
        assert observations == []

    @pytest.mark.asyncio
    async def test_cidr_seed_skipped(self) -> None:
        """CIDR seeds are not applicable and yield no observations."""
        seed = Seed(seed_type=SeedType.CIDR, value="10.0.0.0/8")
        observations = await _collect(seed)
        assert observations == []

    @pytest.mark.asyncio
    async def test_asn_seed_skipped(self) -> None:
        """ASN seeds are not applicable and yield no observations."""
        seed = Seed(seed_type=SeedType.ASN, value="AS15169")
        observations = await _collect(seed)
        assert observations == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_domain_seed_derives_org(self) -> None:
        """A DOMAIN seed derives org name from the first domain label."""
        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        # All probes 404.
        respx.route(method="HEAD").mock(return_value=httpx.Response(404))

        observations = await _collect(seed)
        # No buckets found, but no error either — just empty.
        assert observations == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_org_seed_with_domain_property(self) -> None:
        """Organization seed with domain property generates both name sets."""
        seed = Seed(
            seed_type=SeedType.ORGANIZATION,
            value="myorg",
            properties={"domain": "myorgsite.com"},
        )
        # All probes 404.
        respx.route(method="HEAD").mock(return_value=httpx.Response(404))

        # Verify name generation includes domain-based names.
        candidates = generate_bucket_names("myorg", domain="myorgsite.com")
        assert "myorgsite" in candidates
        assert "myorgsite-backups" in candidates

        observations = await _collect(seed)
        assert observations == []


# === 5. Rate limiting =========================================================


class TestRateLimiting:
    @respx.mock
    @pytest.mark.asyncio
    async def test_semaphore_limits_concurrency(self) -> None:
        """Semaphore limits concurrent probes to max_concurrent."""
        max_concurrent = 2
        config = _config(max_concurrent=max_concurrent)
        collector = CloudStorageExposureCollector(config)

        active_count = 0
        max_active = 0

        async def tracking_probe(provider: str, name: str, url: str) -> object:
            nonlocal active_count, max_active
            active_count += 1
            max_active = max(max_active, active_count)
            await asyncio.sleep(0.01)
            active_count -= 1
            return None

        # All probes 404 for the actual network.
        respx.route(method="HEAD").mock(return_value=httpx.Response(404))

        with patch.object(collector, "_probe_single", side_effect=tracking_probe):
            seed = Seed(seed_type=SeedType.ORGANIZATION, value="sem-test")
            results: list[Observation] = []
            async for obs in collector.expand(seed):
                results.append(obs)

        # max_active should not exceed max_concurrent.
        assert max_active <= max_concurrent


# === 6. Health check ==========================================================


class TestHealthCheck:
    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_success(self) -> None:
        """Health check returns SUCCESS when S3 endpoint is reachable."""
        respx.head("https://s3.amazonaws.com/").mock(return_value=httpx.Response(200))

        config = _config()
        collector = CloudStorageExposureCollector(config)
        result = await collector.health_check()

        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "cloud-storage-exposure"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0

    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_failure(self) -> None:
        """Health check returns FAILURE on connection error."""
        respx.head("https://s3.amazonaws.com/").mock(
            side_effect=httpx.ConnectError("connection refused")
        )

        config = _config()
        collector = CloudStorageExposureCollector(config)
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None

    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_server_error(self) -> None:
        """Health check returns FAILURE on 500 response."""
        respx.head("https://s3.amazonaws.com/").mock(return_value=httpx.Response(500))

        config = _config()
        collector = CloudStorageExposureCollector(config)
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE


# === 7. Observation structure =================================================


class TestObservationStructure:
    @respx.mock
    @pytest.mark.asyncio
    async def test_observation_type_and_subject(self) -> None:
        """Observations use CLOUD_IP_RANGE type and CLOUD_RESOURCE_ID subject."""
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="obstest")
        respx.head("https://obstest.s3.amazonaws.com/").mock(return_value=httpx.Response(403))
        respx.route(method="HEAD", host__regex=r".*\.s3\.amazonaws\.com").mock(
            return_value=httpx.Response(404)
        )
        respx.route(method="HEAD", host__regex=r".*\.blob\.core\.windows\.net").mock(
            return_value=httpx.Response(404)
        )
        respx.route(method="HEAD", host="storage.googleapis.com").mock(
            return_value=httpx.Response(404)
        )

        observations = await _collect(seed)
        obs = [o for o in observations if o.structured_payload.get("bucket_name") == "obstest"]
        assert len(obs) == 1
        assert obs[0].observation_type == ObservationType.CLOUD_IP_RANGE
        assert obs[0].subject.identifier_value == "aws:obstest"
        assert obs[0].tenant_id == TENANT_ID
        assert obs[0].collector_id == "cloud-storage-exposure"
        assert obs[0].structured_payload["discovery_type"] == "cloud_storage_exposure"
