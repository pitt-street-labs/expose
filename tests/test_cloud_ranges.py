"""Tests for the cloud-ranges collector (Tier 1, passive).

Verifies IP/CIDR containment checks against cached AWS, Azure, and GCP IP
range manifests. All tests use local fixture files — no live network calls.

Coverage:
1. Happy path: IP matches AWS range
2. Happy path: IP matches Azure range
3. Happy path: IP matches GCP range
4. CIDR seed: containment via overlap
5. No match: IP not in any cloud range
6. Non-IP/CIDR seed: silently skipped
7. Missing/corrupt cache file: health_check returns failure
8. IPv6 address matching
9. Health check succeeds with valid cache
10. Partial load: some files present, some missing
"""

from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

from expose.collectors.base import (
    CollectorConfig,
    Observation,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.builtin.cloud_ranges import CloudRangesCollector
from expose.collectors.registry import DEFAULT_REGISTRY
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, IdentifierType

# Synthetic IDs consistent with the project's test convention.
TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000D001")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000D002")

# Path to committed fixture files.
_FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "collectors" / "cloud_ranges"


def _make_config(ranges_dir: Path | str | None = None) -> CollectorConfig:
    """Build a ``CollectorConfig`` with the given ranges_dir in extra."""
    extra: dict[str, object] = {}
    if ranges_dir is not None:
        extra["ranges_dir"] = str(ranges_dir)
    return CollectorConfig(
        tenant_id=TENANT_ID,
        run_id=RUN_ID,
        extra=extra,
    )


def _setup_cache(
    tmp_path: Path,
    *,
    aws: bool = True,
    azure: bool = True,
    gcp: bool = True,
) -> Path:
    """Copy fixture JSON files into tmp_path, optionally skipping providers.

    Returns the cache directory path.
    """
    cache_dir = tmp_path / "cloud_ranges_cache"
    cache_dir.mkdir(exist_ok=True)
    if aws:
        src = _FIXTURES_DIR / "aws-ip-ranges.json"
        (cache_dir / "aws-ip-ranges.json").write_text(src.read_text())
    if azure:
        src = _FIXTURES_DIR / "azure-ip-ranges.json"
        (cache_dir / "azure-ip-ranges.json").write_text(src.read_text())
    if gcp:
        src = _FIXTURES_DIR / "gcp-ip-ranges.json"
        (cache_dir / "gcp-ip-ranges.json").write_text(src.read_text())
    return cache_dir


async def _collect_all(collector: CloudRangesCollector, seed: Seed) -> list[Observation]:
    """Drain the async generator into a list."""
    results: list[Observation] = []
    async for obs in collector.expand(seed):
        results.append(obs)
    return results


# === 1. Happy path: IP matches AWS range =====================================

async def test_ip_matches_aws_range(tmp_path: Path) -> None:
    """An IP within an AWS prefix yields a CLOUD_IP_RANGE observation."""
    cache_dir = _setup_cache(tmp_path)
    config = _make_config(cache_dir)
    collector = CloudRangesCollector(config)

    # 3.5.140.1 falls within 3.5.140.0/22
    seed = Seed(seed_type=SeedType.IP, value="3.5.140.1")
    results = await _collect_all(collector, seed)

    assert len(results) == 1
    obs = results[0]
    assert obs.observation_type == ObservationType.CLOUD_IP_RANGE
    assert obs.collector_id == "cloud-ranges"
    assert obs.tenant_id == TENANT_ID
    assert obs.subject.identifier_type == IdentifierType.IP
    assert obs.subject.identifier_value == "3.5.140.1"
    assert obs.structured_payload["provider"] == "aws"
    assert obs.structured_payload["region"] == "ap-northeast-2"
    assert obs.structured_payload["service"] == "AMAZON"
    assert obs.structured_payload["prefix"] == "3.5.140.0/22"


# === 2. Happy path: IP matches Azure range ===================================

async def test_ip_matches_azure_range(tmp_path: Path) -> None:
    """An IP within an Azure address prefix yields a CLOUD_IP_RANGE observation."""
    cache_dir = _setup_cache(tmp_path)
    config = _make_config(cache_dir)
    collector = CloudRangesCollector(config)

    # 40.71.5.10 falls within 40.71.0.0/16
    seed = Seed(seed_type=SeedType.IP, value="40.71.5.10")
    results = await _collect_all(collector, seed)

    assert len(results) == 1
    obs = results[0]
    assert obs.observation_type == ObservationType.CLOUD_IP_RANGE
    assert obs.structured_payload["provider"] == "azure"
    assert obs.structured_payload["region"] == "eastus"
    assert obs.structured_payload["prefix"] == "40.71.0.0/16"


# === 3. Happy path: IP matches GCP range ====================================

async def test_ip_matches_gcp_range(tmp_path: Path) -> None:
    """An IP within a GCP prefix yields a CLOUD_IP_RANGE observation."""
    cache_dir = _setup_cache(tmp_path)
    config = _make_config(cache_dir)
    collector = CloudRangesCollector(config)

    # 35.186.1.100 falls within 35.186.0.0/16
    seed = Seed(seed_type=SeedType.IP, value="35.186.1.100")
    results = await _collect_all(collector, seed)

    assert len(results) == 1
    obs = results[0]
    assert obs.observation_type == ObservationType.CLOUD_IP_RANGE
    assert obs.structured_payload["provider"] == "gcp"
    assert obs.structured_payload["region"] == "us-central1"
    assert obs.structured_payload["service"] == "Google Cloud"
    assert obs.structured_payload["prefix"] == "35.186.0.0/16"


# === 4. CIDR seed: containment via overlap ===================================

async def test_cidr_seed_matches(tmp_path: Path) -> None:
    """A CIDR seed that overlaps with a cloud range yields observations."""
    cache_dir = _setup_cache(tmp_path)
    config = _make_config(cache_dir)
    collector = CloudRangesCollector(config)

    # 3.5.141.0/24 is a subset of AWS 3.5.140.0/22
    seed = Seed(seed_type=SeedType.CIDR, value="3.5.141.0/24")
    results = await _collect_all(collector, seed)

    assert len(results) == 1
    obs = results[0]
    assert obs.observation_type == ObservationType.CLOUD_IP_RANGE
    assert obs.subject.identifier_type == IdentifierType.CIDR
    assert obs.subject.identifier_value == "3.5.141.0/24"
    assert obs.structured_payload["provider"] == "aws"
    assert obs.structured_payload["prefix"] == "3.5.140.0/22"


# === 5. No match: IP not in any cloud range ==================================

async def test_ip_no_match(tmp_path: Path) -> None:
    """An IP not in any cloud range yields zero observations."""
    cache_dir = _setup_cache(tmp_path)
    config = _make_config(cache_dir)
    collector = CloudRangesCollector(config)

    # 192.168.1.1 is RFC 1918 private — not in any cloud range fixture.
    seed = Seed(seed_type=SeedType.IP, value="192.168.1.1")
    results = await _collect_all(collector, seed)

    assert len(results) == 0


# === 6. Non-IP/CIDR seed: silently skipped ===================================

async def test_non_ip_seed_skipped(tmp_path: Path) -> None:
    """A DOMAIN seed is silently skipped — no observations, no errors."""
    cache_dir = _setup_cache(tmp_path)
    config = _make_config(cache_dir)
    collector = CloudRangesCollector(config)

    seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
    results = await _collect_all(collector, seed)

    assert len(results) == 0


# === 7. Missing/corrupt cache file: health_check returns failure ==============

async def test_health_check_failure_missing_dir(tmp_path: Path) -> None:
    """health_check returns FAILURE when the ranges_dir does not exist."""
    nonexistent = tmp_path / "does_not_exist"
    config = _make_config(nonexistent)
    collector = CloudRangesCollector(config)

    health = await collector.health_check()

    assert health.status == CollectorStatus.FAILURE
    assert health.error_message is not None
    assert "not found" in health.error_message.lower()


async def test_health_check_failure_corrupt_file(tmp_path: Path) -> None:
    """health_check returns FAILURE when cache files contain invalid JSON."""
    cache_dir = tmp_path / "corrupt_cache"
    cache_dir.mkdir()
    (cache_dir / "aws-ip-ranges.json").write_text("NOT VALID JSON {{{")
    (cache_dir / "azure-ip-ranges.json").write_text("ALSO BAD")
    (cache_dir / "gcp-ip-ranges.json").write_text("NOPE")

    config = _make_config(cache_dir)
    collector = CloudRangesCollector(config)

    health = await collector.health_check()

    assert health.status == CollectorStatus.FAILURE
    assert health.error_message is not None
    assert "corrupt" in health.error_message.lower()


# === 8. IPv6 address matching ================================================

async def test_ipv6_matches_aws_range(tmp_path: Path) -> None:
    """An IPv6 address within an AWS IPv6 prefix yields an observation."""
    cache_dir = _setup_cache(tmp_path)
    config = _make_config(cache_dir)
    collector = CloudRangesCollector(config)

    # 2600:1f69:8000::1 falls within 2600:1f69:8000::/40
    seed = Seed(seed_type=SeedType.IP, value="2600:1f69:8000::1")
    results = await _collect_all(collector, seed)

    assert len(results) == 1
    obs = results[0]
    assert obs.observation_type == ObservationType.CLOUD_IP_RANGE
    assert obs.subject.identifier_type == IdentifierType.IP
    assert obs.subject.identifier_value == "2600:1f69:8000::1"
    assert obs.structured_payload["provider"] == "aws"
    assert obs.structured_payload["region"] == "us-west-2"


async def test_ipv6_matches_azure_range(tmp_path: Path) -> None:
    """An IPv6 address within an Azure prefix yields an observation."""
    cache_dir = _setup_cache(tmp_path)
    config = _make_config(cache_dir)
    collector = CloudRangesCollector(config)

    # 2603:1020:200::1 falls within 2603:1020:200::/48
    seed = Seed(seed_type=SeedType.IP, value="2603:1020:0200::1")
    results = await _collect_all(collector, seed)

    assert len(results) == 1
    obs = results[0]
    assert obs.structured_payload["provider"] == "azure"
    assert obs.structured_payload["region"] == "westeurope"


# === 9. Health check succeeds with valid cache ================================

async def test_health_check_success(tmp_path: Path) -> None:
    """health_check returns SUCCESS when all cache files are loaded."""
    cache_dir = _setup_cache(tmp_path)
    config = _make_config(cache_dir)
    collector = CloudRangesCollector(config)

    health = await collector.health_check()

    assert health.status == CollectorStatus.SUCCESS
    assert health.collector_id == "cloud-ranges"
    assert health.collector_version == "0.1.0"
    assert health.error_message is None
    assert health.detail["prefix_count"] > 0


# === 10. Partial load: some files present, some missing =======================

async def test_health_check_partial_success(tmp_path: Path) -> None:
    """health_check returns PARTIAL_SUCCESS when some files are missing."""
    # Only create the AWS file.
    cache_dir = _setup_cache(tmp_path, aws=True, azure=False, gcp=False)
    config = _make_config(cache_dir)
    collector = CloudRangesCollector(config)

    health = await collector.health_check()

    assert health.status == CollectorStatus.PARTIAL_SUCCESS
    assert health.error_message is not None
    assert health.detail["prefix_count"] > 0
    assert len(health.detail["errors"]) == 2


# === 11. No ranges_dir configured ============================================

async def test_health_check_no_ranges_dir() -> None:
    """health_check returns FAILURE when no ranges_dir is configured."""
    config = _make_config(ranges_dir=None)
    collector = CloudRangesCollector(config)

    health = await collector.health_check()

    assert health.status == CollectorStatus.FAILURE
    assert health.error_message is not None


# === 12. Collector metadata ===================================================

def test_collector_metadata() -> None:
    """Verify class-level metadata attributes."""
    assert CloudRangesCollector.collector_id == "cloud-ranges"
    assert CloudRangesCollector.collector_version == "0.1.0"
    assert CloudRangesCollector.tier == CollectorTier.TIER_1
    assert CloudRangesCollector.requires_credentials is False


# === 13. Registration ========================================================

def test_registered_in_default_registry() -> None:
    """The collector is registered in the default registry at import time."""
    assert DEFAULT_REGISTRY.is_registered("cloud-ranges")
    cls = DEFAULT_REGISTRY.get("cloud-ranges")
    assert cls is CloudRangesCollector


# === 14. Multiple matches for same IP ========================================

async def test_ip_multiple_matches(tmp_path: Path) -> None:
    """An IP that falls into overlapping ranges yields multiple observations."""
    # Create a custom fixture with overlapping prefixes across providers.
    cache_dir = tmp_path / "multi_match_cache"
    cache_dir.mkdir()

    aws_data = {
        "prefixes": [
            {"ip_prefix": "10.0.0.0/8", "region": "us-east-1", "service": "AMAZON"},
            {"ip_prefix": "10.0.0.0/16", "region": "us-west-2", "service": "EC2"},
        ],
        "ipv6_prefixes": [],
    }
    (cache_dir / "aws-ip-ranges.json").write_text(json.dumps(aws_data))
    (cache_dir / "azure-ip-ranges.json").write_text(json.dumps({"values": []}))
    (cache_dir / "gcp-ip-ranges.json").write_text(json.dumps({"prefixes": []}))

    config = _make_config(cache_dir)
    collector = CloudRangesCollector(config)

    seed = Seed(seed_type=SeedType.IP, value="10.0.1.1")
    results = await _collect_all(collector, seed)

    assert len(results) == 2
    providers = {obs.structured_payload["prefix"] for obs in results}
    assert "10.0.0.0/8" in providers
    assert "10.0.0.0/16" in providers
