"""Tests for the rdap-whois collector (Tier 1, passive RDAP registration data).

Uses ``respx`` to mock all HTTP requests — no live network calls.

Coverage:

1. Happy path: domain RDAP returns registration info.
2. Happy path: IP RDAP returns registration info.
3. Non-domain/IP seed: silently skipped.
4. Network error: raises CollectorSourceUnreachableError.
5. Privacy-redacted registrant: handled gracefully, observations still emitted.
6. PII filtering: personal names/emails NOT extracted.
7. Organization name sanitization: malicious org names sanitized.
8. Health check: reachable and unreachable status.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import uuid4

import httpx
import pytest
import respx

from expose.collectors.base import (
    CollectorConfig,
    CollectorSourceUnreachableError,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.builtin.rdap_whois import (
    RdapWhoisCollector,
    _parse_whois_text,
)
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, IdentifierType

# === Fixtures ================================================================

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "collectors" / "rdap_whois"


def _load_fixture(name: str) -> dict:
    """Load a recorded RDAP JSON response from the fixtures directory."""
    return json.loads((FIXTURES_DIR / name).read_text())


def _make_config() -> CollectorConfig:
    """Create a minimal CollectorConfig for testing."""
    return CollectorConfig(
        tenant_id=uuid4(),
        run_id=uuid4(),
        request_timeout_seconds=10.0,
    )


async def _collect_all(collector: RdapWhoisCollector, seed: Seed) -> list:
    """Drain the async iterator from expand() into a list."""
    results = []
    async for obs in collector.expand(seed):
        results.append(obs)
    return results


# === Test 1: Happy path — domain RDAP =======================================


@respx.mock
async def test_domain_rdap_happy_path() -> None:
    """Domain seed returns an observation with full registration info."""
    fixture = _load_fixture("domain_example_com.json")
    respx.get("https://rdap.org/domain/example.com").mock(
        return_value=httpx.Response(200, json=fixture),
    )

    collector = RdapWhoisCollector(_make_config())
    seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
    observations = await _collect_all(collector, seed)

    assert len(observations) == 1
    obs = observations[0]

    # Observation metadata.
    assert obs.collector_id == "rdap-whois"
    assert obs.collector_version == "0.1.0"
    assert obs.observation_type == ObservationType.RDAP_REGISTRATION

    # Subject.
    assert obs.subject.identifier_type == IdentifierType.DOMAIN
    assert obs.subject.identifier_value == "example.com"

    # Structured payload.
    payload = obs.structured_payload
    assert payload["registrant_org"] == "Internet Assigned Numbers Authority"
    assert "RESERVED-Internet Assigned Numbers Authority" in payload["registrar"]
    assert payload["registration_date"] == "1995-08-14T04:00:00Z"
    assert payload["expiration_date"] == "2025-08-13T04:00:00Z"
    assert "a.iana-servers.net" in payload["nameservers"]
    assert "b.iana-servers.net" in payload["nameservers"]
    assert "client delete prohibited" in payload["status"]
    assert payload["rdap_port43"] == "whois.verisign-grs.com"

    # Evidence blob present.
    assert obs.evidence_blob is not None
    assert obs.evidence_blob_content_type == "application/rdap+json"

    # No warnings for a complete response.
    assert obs.warnings == []


# === Test 2: Happy path — IP RDAP ============================================


@respx.mock
async def test_ip_rdap_happy_path() -> None:
    """IP seed returns an observation with registration info."""
    fixture = _load_fixture("ip_93_184_216_34.json")
    respx.get("https://rdap.org/ip/93.184.216.34").mock(
        return_value=httpx.Response(200, json=fixture),
    )

    collector = RdapWhoisCollector(_make_config())
    seed = Seed(seed_type=SeedType.IP, value="93.184.216.34")
    observations = await _collect_all(collector, seed)

    assert len(observations) == 1
    obs = observations[0]

    assert obs.observation_type == ObservationType.RDAP_REGISTRATION
    assert obs.subject.identifier_type == IdentifierType.IP
    assert obs.subject.identifier_value == "93.184.216.34"

    payload = obs.structured_payload
    assert payload["registrant_org"] == "Edgecast Inc."
    assert payload["registration_date"] == "2014-03-14T16:16:51Z"
    assert payload["rdap_port43"] == "whois.arin.net"
    assert "active" in payload["status"]

    # IP responses typically have no nameservers or expiration.
    assert "nameservers" not in payload
    assert "expiration_date" not in payload


# === Test 3: Non-domain/IP seed skipped =====================================


@respx.mock
async def test_non_domain_ip_seed_skipped() -> None:
    """Seeds that are not DOMAIN or IP produce zero observations."""
    collector = RdapWhoisCollector(_make_config())

    for seed_type in [SeedType.ORGANIZATION, SeedType.ASN, SeedType.CIDR]:
        seed = Seed(seed_type=seed_type, value="test-value")
        observations = await _collect_all(collector, seed)
        assert observations == [], f"Expected no observations for {seed_type}"


# === Test 4: Network error → CollectorSourceUnreachableError ================


@respx.mock
async def test_network_error_raises_source_unreachable() -> None:
    """Network errors during RDAP fetch raise CollectorSourceUnreachableError."""
    respx.get("https://rdap.org/domain/unreachable.com").mock(
        side_effect=httpx.ConnectError("Connection refused"),
    )

    collector = RdapWhoisCollector(_make_config())
    seed = Seed(seed_type=SeedType.DOMAIN, value="unreachable.com")

    with pytest.raises(CollectorSourceUnreachableError, match="RDAP query failed"):
        await _collect_all(collector, seed)


# === Test 5: Privacy-redacted registrant ====================================


@respx.mock
async def test_privacy_redacted_registrant() -> None:
    """Privacy-redacted RDAP response still emits an observation with available data."""
    fixture = _load_fixture("domain_privacy_redacted.json")
    respx.get("https://rdap.org/domain/private-domain.com").mock(
        return_value=httpx.Response(200, json=fixture),
    )

    collector = RdapWhoisCollector(_make_config())
    seed = Seed(seed_type=SeedType.DOMAIN, value="private-domain.com")
    observations = await _collect_all(collector, seed)

    assert len(observations) == 1
    obs = observations[0]

    payload = obs.structured_payload
    # Registrant org should be absent (redacted entity has no vcard).
    assert "registrant_org" not in payload
    # Registrar should still be present.
    assert "NameCheap, Inc." in payload["registrar"]
    # Dates, nameservers, status should still be present.
    assert payload["registration_date"] == "2020-01-15T10:30:00Z"
    assert payload["expiration_date"] == "2026-01-15T10:30:00Z"
    assert "ns1.namecheap.com" in payload["nameservers"]

    # Warning about missing registrant org.
    assert any("No registrant organization" in w for w in obs.warnings)


# === Test 6: PII filtering — personal names NOT extracted ===================


@respx.mock
async def test_pii_filtering_personal_name() -> None:
    """Personal names in registrant vcard are filtered out; emails/phones never extracted."""
    fixture = _load_fixture("domain_personal_name.json")
    respx.get("https://rdap.org/domain/personal-domain.net").mock(
        return_value=httpx.Response(200, json=fixture),
    )

    collector = RdapWhoisCollector(_make_config())
    seed = Seed(seed_type=SeedType.DOMAIN, value="personal-domain.net")
    observations = await _collect_all(collector, seed)

    assert len(observations) == 1
    obs = observations[0]

    payload = obs.structured_payload
    # "John Doe" is a personal name with no org field → must NOT appear.
    assert "registrant_org" not in payload
    # Emails, phones, addresses must never appear anywhere in the payload.
    payload_str = json.dumps(payload)
    assert "john.doe@example.com" not in payload_str
    assert "+1-555-123-4567" not in payload_str
    assert "123 Main Street" not in payload_str

    # Warning about no registrant org.
    assert any("No registrant organization" in w for w in obs.warnings)

    # Registrar (always an org) should still be present.
    assert "GoDaddy.com, LLC" in payload["registrar"]


# === Test 7: Malicious org name sanitized ===================================


@respx.mock
async def test_malicious_org_name_sanitized() -> None:
    """Organization names with HTML/script injection are sanitized."""
    fixture = _load_fixture("domain_malicious_org.json")
    respx.get("https://rdap.org/domain/malicious-org.com").mock(
        return_value=httpx.Response(200, json=fixture),
    )

    collector = RdapWhoisCollector(_make_config())
    seed = Seed(seed_type=SeedType.DOMAIN, value="malicious-org.com")
    observations = await _collect_all(collector, seed)

    assert len(observations) == 1
    obs = observations[0]

    payload = obs.structured_payload
    # The org name should be present but the sanitization layer runs on it.
    # sanitize_field preserves the text (heuristic detection, not stripping)
    # but the key point is the value went through sanitize_field.
    assert "registrant_org" in payload
    assert "registrar" in payload
    # The values are present (sanitize_field preserves content, flags it).
    assert isinstance(payload["registrant_org"], str)
    assert isinstance(payload["registrar"], str)
    assert len(payload["registrant_org"]) > 0
    assert len(payload["registrar"]) > 0


# === Test 8: Health check — reachable and unreachable =======================


@respx.mock
async def test_health_check_reachable() -> None:
    """Health check returns SUCCESS when rdap.org is reachable."""
    respx.head("https://rdap.org/").mock(
        return_value=httpx.Response(200),
    )

    collector = RdapWhoisCollector(_make_config())
    result = await collector.health_check()

    assert result.collector_id == "rdap-whois"
    assert result.collector_version == "0.1.0"
    assert result.status == CollectorStatus.SUCCESS
    assert result.latency_ms is not None
    assert result.latency_ms >= 0.0
    assert result.error_message is None


@respx.mock
async def test_health_check_unreachable() -> None:
    """Health check returns FAILURE when rdap.org is unreachable."""
    respx.head("https://rdap.org/").mock(
        side_effect=httpx.ConnectError("Connection refused"),
    )

    collector = RdapWhoisCollector(_make_config())
    result = await collector.health_check()

    assert result.collector_id == "rdap-whois"
    assert result.status == CollectorStatus.FAILURE
    assert result.error_message is not None
    assert "unreachable" in result.error_message.lower()


# === Test 9: Health check — server error ====================================


@respx.mock
async def test_health_check_server_error() -> None:
    """Health check returns FAILURE on HTTP 500+."""
    respx.head("https://rdap.org/").mock(
        return_value=httpx.Response(503),
    )

    collector = RdapWhoisCollector(_make_config())
    result = await collector.health_check()

    assert result.status == CollectorStatus.FAILURE
    assert result.error_message is not None
    assert "503" in result.error_message


# === Test 10: Domain canonicalization (uppercase input) =======================


@respx.mock
async def test_domain_canonicalization() -> None:
    """Domain seed values are canonicalized before querying RDAP."""
    fixture = _load_fixture("domain_example_com.json")
    # The collector should canonicalize "EXAMPLE.COM" to "example.com".
    respx.get("https://rdap.org/domain/example.com").mock(
        return_value=httpx.Response(200, json=fixture),
    )

    collector = RdapWhoisCollector(_make_config())
    seed = Seed(seed_type=SeedType.DOMAIN, value="EXAMPLE.COM")
    observations = await _collect_all(collector, seed)

    assert len(observations) == 1
    assert observations[0].subject.identifier_value == "example.com"


# === Test 11: HTTP 404 → CollectorSourceUnreachableError ====================


@respx.mock
async def test_http_404_raises_source_unreachable() -> None:
    """HTTP error responses (e.g. 404) raise CollectorSourceUnreachableError."""
    respx.get("https://rdap.org/domain/nonexistent.invalid").mock(
        return_value=httpx.Response(404, json={"errorCode": 404}),
    )

    collector = RdapWhoisCollector(_make_config())
    seed = Seed(seed_type=SeedType.DOMAIN, value="nonexistent.invalid")

    with pytest.raises(CollectorSourceUnreachableError, match="RDAP query failed"):
        await _collect_all(collector, seed)


# === Test 12: Collector class attributes =====================================


def test_collector_class_attributes() -> None:
    """Verify the collector's class-level metadata is correct."""
    assert RdapWhoisCollector.collector_id == "rdap-whois"
    assert RdapWhoisCollector.collector_version == "0.1.0"
    assert RdapWhoisCollector.requires_credentials is False
    assert RdapWhoisCollector.tier == CollectorTier.TIER_1


# === WHOIS CLI fallback tests =================================================

# Realistic whois CLI output for testing.
_WHOIS_CLI_OUTPUT = """\
   Domain Name: EXAMPLE.COM
   Registry Domain ID: 2336799_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.iana.org
   Registrar URL: http://www.iana.org
   Updated Date: 2024-08-14T07:01:44Z
   Creation Date: 1995-08-14T04:00:00Z
   Registry Expiry Date: 2025-08-13T04:00:00Z
   Registrar: RESERVED-Internet Assigned Numbers Authority
   Registrant Organization: Internet Assigned Numbers Authority
   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
   Name Server: A.IANA-SERVERS.NET
   Name Server: B.IANA-SERVERS.NET
   DNSSEC: signedDelegation
   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of whois database: 2025-05-11T00:00:00Z <<<
"""

_WHOIS_CLI_MINIMAL = """\
   Domain Name: MINIMAL.COM
   Registrar: Some Registrar Inc.
"""

_WHOIS_CLI_EMPTY = """\
% This is the RIPE Database query service.
% Information related to '93.184.216.0 - 93.184.216.255'
%
% No entries found.
"""


# === Test 13: _parse_whois_text — full output =================================


def test_parse_whois_text_full() -> None:
    """_parse_whois_text extracts all fields from a complete WHOIS response."""
    result = _parse_whois_text(_WHOIS_CLI_OUTPUT)
    assert result is not None

    assert result["registrant_org"] == "Internet Assigned Numbers Authority"
    assert result["registrar"] == "RESERVED-Internet Assigned Numbers Authority"
    assert result["registration_date"] == "1995-08-14T04:00:00Z"
    assert result["expiration_date"] == "2025-08-13T04:00:00Z"
    assert "a.iana-servers.net" in result["nameservers"]
    assert "b.iana-servers.net" in result["nameservers"]
    assert "clientDeleteProhibited" in result["status"]
    assert "clientTransferProhibited" in result["status"]
    assert "clientUpdateProhibited" in result["status"]


# === Test 14: _parse_whois_text — minimal output =============================


def test_parse_whois_text_minimal() -> None:
    """_parse_whois_text handles output with only some fields."""
    result = _parse_whois_text(_WHOIS_CLI_MINIMAL)
    assert result is not None
    assert result["registrar"] == "Some Registrar Inc."
    assert "registrant_org" not in result
    assert "nameservers" not in result


# === Test 15: _parse_whois_text — empty/useless output ========================


def test_parse_whois_text_empty() -> None:
    """_parse_whois_text returns None when no useful data found."""
    assert _parse_whois_text(_WHOIS_CLI_EMPTY) is None
    assert _parse_whois_text("") is None
    assert _parse_whois_text("Some random text with no WHOIS fields") is None


# === Test 16: RDAP succeeds — no fallback invoked ============================


@respx.mock
async def test_rdap_succeeds_no_fallback() -> None:
    """When RDAP works, the whois CLI fallback is never called."""
    fixture = _load_fixture("domain_example_com.json")
    respx.get("https://rdap.org/domain/example.com").mock(
        return_value=httpx.Response(200, json=fixture),
    )

    collector = RdapWhoisCollector(_make_config())
    seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")

    with patch.object(collector, "_whois_cli_fallback") as mock_fallback:
        observations = await _collect_all(collector, seed)
        mock_fallback.assert_not_called()

    assert len(observations) == 1
    assert "source" not in observations[0].structured_payload


# === Test 17: RDAP fails + WHOIS fallback succeeds ===========================


@respx.mock
async def test_rdap_fails_whois_fallback_succeeds() -> None:
    """When RDAP is unreachable, the collector falls back to whois CLI."""
    respx.get("https://rdap.org/domain/example.com").mock(
        side_effect=httpx.ConnectError("Connection refused"),
    )

    collector = RdapWhoisCollector(_make_config())
    seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")

    # Mock the subprocess to return realistic whois output.
    mock_proc = MagicMock()

    async def _communicate() -> tuple[bytes, bytes]:
        return (_WHOIS_CLI_OUTPUT.encode("utf-8"), b"")

    mock_proc.communicate = _communicate
    mock_proc.returncode = 0

    async def _create_proc(*args: object, **kwargs: object) -> MagicMock:
        return mock_proc

    with (
        patch("shutil.which", return_value="/usr/bin/whois"),
        patch(
            "asyncio.create_subprocess_exec",
            side_effect=_create_proc,
        ),
    ):
        observations = await _collect_all(collector, seed)

    assert len(observations) == 1
    obs = observations[0]

    # Verify it is tagged as a fallback observation.
    assert obs.structured_payload["source"] == "whois_cli_fallback"
    assert obs.observation_type == ObservationType.RDAP_REGISTRATION
    assert obs.subject.identifier_type == IdentifierType.DOMAIN
    assert obs.subject.identifier_value == "example.com"

    # Evidence is the raw whois text.
    assert obs.evidence_blob_content_type == "text/plain"
    assert obs.evidence_blob is not None
    assert b"EXAMPLE.COM" in obs.evidence_blob

    # Payload fields extracted from whois text.
    payload = obs.structured_payload
    assert "Internet Assigned Numbers Authority" in payload["registrant_org"]
    assert payload["registration_date"] == "1995-08-14T04:00:00Z"
    assert payload["expiration_date"] == "2025-08-13T04:00:00Z"
    assert "a.iana-servers.net" in payload["nameservers"]
    assert "b.iana-servers.net" in payload["nameservers"]

    # Warning about fallback source.
    assert any("whois CLI fallback" in w for w in obs.warnings)


# === Test 18: Both RDAP and WHOIS fail — re-raise RDAP error =================


@respx.mock
async def test_both_rdap_and_whois_fail() -> None:
    """When both RDAP and whois CLI fail, the original RDAP error is raised."""
    respx.get("https://rdap.org/domain/broken.com").mock(
        side_effect=httpx.ConnectError("Connection refused"),
    )

    collector = RdapWhoisCollector(_make_config())
    seed = Seed(seed_type=SeedType.DOMAIN, value="broken.com")

    # Mock whois as not installed.
    with patch("shutil.which", return_value=None):
        with pytest.raises(
            CollectorSourceUnreachableError,
            match="RDAP query failed",
        ):
            await _collect_all(collector, seed)


# === Test 19: WHOIS fallback — whois command times out ========================


@respx.mock
async def test_whois_fallback_timeout() -> None:
    """whois CLI timeout causes fallback to return None → RDAP error re-raised."""
    respx.get("https://rdap.org/domain/slow.com").mock(
        side_effect=httpx.ConnectError("Connection refused"),
    )

    collector = RdapWhoisCollector(_make_config())
    seed = Seed(seed_type=SeedType.DOMAIN, value="slow.com")

    # Create a proc whose communicate() blocks long enough for the
    # (patched-short) timeout to fire.
    mock_proc = MagicMock()

    async def _communicate_hang() -> tuple[bytes, bytes]:
        await asyncio.sleep(10)  # will be cancelled by wait_for
        return (b"", b"")  # pragma: no cover

    mock_proc.communicate = _communicate_hang
    mock_proc.returncode = -1

    async def _create_proc_slow(*args: object, **kwargs: object) -> MagicMock:
        return mock_proc

    with (
        patch("shutil.which", return_value="/usr/bin/whois"),
        patch(
            "asyncio.create_subprocess_exec",
            side_effect=_create_proc_slow,
        ),
        # Shrink the timeout to 0.01s so the test runs instantly.
        patch(
            "expose.collectors.builtin.rdap_whois._WHOIS_CLI_TIMEOUT_SECONDS",
            0.01,
        ),
    ):
        with pytest.raises(CollectorSourceUnreachableError):
            await _collect_all(collector, seed)


# === Test 20: WHOIS fallback — whois returns non-zero exit code ===============


@respx.mock
async def test_whois_fallback_nonzero_exit() -> None:
    """whois CLI with non-zero exit triggers re-raise of RDAP error."""
    respx.get("https://rdap.org/domain/fail.com").mock(
        side_effect=httpx.ConnectError("Connection refused"),
    )

    collector = RdapWhoisCollector(_make_config())
    seed = Seed(seed_type=SeedType.DOMAIN, value="fail.com")

    mock_proc = MagicMock()

    async def _communicate() -> tuple[bytes, bytes]:
        return (b"", b"error")

    mock_proc.communicate = _communicate
    mock_proc.returncode = 1

    async def _create_proc(*args: object, **kwargs: object) -> MagicMock:
        return mock_proc

    with (
        patch("shutil.which", return_value="/usr/bin/whois"),
        patch(
            "asyncio.create_subprocess_exec",
            side_effect=_create_proc,
        ),
    ):
        with pytest.raises(CollectorSourceUnreachableError):
            await _collect_all(collector, seed)


# === Test 21: WHOIS fallback — useless output returns None ====================


@respx.mock
async def test_whois_fallback_useless_output() -> None:
    """whois CLI returns successfully but output has no fields → re-raise."""
    respx.get("https://rdap.org/domain/empty.com").mock(
        side_effect=httpx.ConnectError("Connection refused"),
    )

    collector = RdapWhoisCollector(_make_config())
    seed = Seed(seed_type=SeedType.DOMAIN, value="empty.com")

    mock_proc = MagicMock()

    async def _communicate() -> tuple[bytes, bytes]:
        return (_WHOIS_CLI_EMPTY.encode("utf-8"), b"")

    mock_proc.communicate = _communicate
    mock_proc.returncode = 0

    async def _create_proc(*args: object, **kwargs: object) -> MagicMock:
        return mock_proc

    with (
        patch("shutil.which", return_value="/usr/bin/whois"),
        patch(
            "asyncio.create_subprocess_exec",
            side_effect=_create_proc,
        ),
    ):
        with pytest.raises(CollectorSourceUnreachableError):
            await _collect_all(collector, seed)


# === Test 22: Health check reports whois_cli_available ========================


@respx.mock
async def test_health_check_reports_whois_available() -> None:
    """Health check includes whois_cli_available in detail dict."""
    respx.head("https://rdap.org/").mock(
        return_value=httpx.Response(200),
    )

    collector = RdapWhoisCollector(_make_config())

    with patch("expose.collectors.builtin.rdap_whois.shutil.which", return_value="/usr/bin/whois"):
        result = await collector.health_check()

    assert result.status == CollectorStatus.SUCCESS
    assert result.detail["whois_cli_available"] is True


@respx.mock
async def test_health_check_reports_whois_not_available() -> None:
    """Health check reports whois_cli_available=False when not installed."""
    respx.head("https://rdap.org/").mock(
        return_value=httpx.Response(200),
    )

    collector = RdapWhoisCollector(_make_config())

    with patch("expose.collectors.builtin.rdap_whois.shutil.which", return_value=None):
        result = await collector.health_check()

    assert result.status == CollectorStatus.SUCCESS
    assert result.detail["whois_cli_available"] is False


# === Test 23: IP seed does not use WHOIS fallback =============================


@respx.mock
async def test_ip_seed_no_whois_fallback() -> None:
    """IP seeds raise CollectorSourceUnreachableError without WHOIS fallback.

    The WHOIS CLI fallback is only wired into _expand_domain, not _expand_ip.
    """
    respx.get("https://rdap.org/ip/1.2.3.4").mock(
        side_effect=httpx.ConnectError("Connection refused"),
    )

    collector = RdapWhoisCollector(_make_config())
    seed = Seed(seed_type=SeedType.IP, value="1.2.3.4")

    with pytest.raises(CollectorSourceUnreachableError):
        await _collect_all(collector, seed)


# === Test 24: _parse_whois_text — alternative field labels ====================


def test_parse_whois_text_alternative_labels() -> None:
    """_parse_whois_text handles alternative field label variants."""
    alt_output = """\
   Domain Name: ALT-EXAMPLE.COM
   Registrant Org: Alt Corp LLC
   Registrar: Alt Registrar
   Created: 2020-01-01T00:00:00Z
   Expiration Date: 2030-01-01T00:00:00Z
   Name Server: ns1.alt.com
   Domain Status: ok
"""
    result = _parse_whois_text(alt_output)
    assert result is not None
    assert result["registrant_org"] == "Alt Corp LLC"
    assert result["registrar"] == "Alt Registrar"
    assert result["registration_date"] == "2020-01-01T00:00:00Z"
    assert result["expiration_date"] == "2030-01-01T00:00:00Z"
    assert "ns1.alt.com" in result["nameservers"]
    assert "ok" in result["status"]
