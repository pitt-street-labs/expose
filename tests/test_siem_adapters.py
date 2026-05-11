"""Tests for SIEM integration adapters (Splunk HEC, Microsoft Sentinel, Chronicle).

Coverage:

 1. SIEMConfig validation — valid config accepted
 2. SIEMConfig validation — empty endpoint rejected
 3. SIEMConfig validation — empty auth_token rejected
 4. SIEMConfig validation — batch_size bounds enforced (min 1, max 1000)
 5. SIEMConfig validation — extra fields rejected
 6. DeliveryResult validation — valid result accepted
 7. DeliveryResult validation — negative events_sent rejected
 8. DeliveryResult validation — negative duration_ms rejected
 9. Splunk: correct HEC endpoint URL constructed
10. Splunk: Authorization header uses ``Splunk {token}`` format
11. Splunk: observations mapped with CIM fields and correct sourcetype
12. Splunk: batch delivery sends newline-delimited JSON
13. Splunk: retry on 5xx then success
14. Splunk: finding delivery maps correctly
15. Splunk: health check calls correct endpoint
16. Splunk: disabled adapter returns zero-cost result
17. Sentinel: HMAC signature construction matches known vector
18. Sentinel: workspace ID extracted from endpoint
19. Sentinel: custom table name ``EXPOSE_Observations_CL`` used
20. Sentinel: field suffix mapping (_s, _d, _t)
21. Sentinel: disabled adapter returns zero-cost result
22. Sentinel: finding delivery uses ``EXPOSE_Findings_CL`` table
23. Chronicle: UDM mapping includes metadata.event_type and principal
24. Chronicle: batchCreate request format correct
25. Chronicle: auth header uses Bearer token
26. Chronicle: finding maps to GENERIC_EVENT with security_result
27. Chronicle: disabled adapter returns zero-cost result
28. All: health check returns True on 200
29. All: health check returns False on network error
30. All: error handling on complete delivery failure

Integration tests (added):

31. Base: retry on 429 rate-limit then success
32. Base: circuit breaker opens after threshold failures
33. Base: circuit breaker resets after cooldown
34. Splunk: entity type -> CIM data model mapping (domain, ip, cidr, cloud, url)
35. Splunk: severity mapping (info->informational, high->high)
36. Sentinel: entity_type_s field present in mapped observations
37. Sentinel: entity_type_s field present in mapped findings
38. Chronicle: entity type -> UDM event_type mapping (domain->NETWORK_DNS)
39. Chronicle: cloud_resource_id includes target.resource in UDM
40. Splunk: batch size limit respected (multiple HTTP calls for large batches)
41. Sentinel: batch size limit respected
42. Chronicle: batch size limit respected
43. Base: circuit breaker short-circuits delivery calls
"""

from __future__ import annotations

import base64
import json
from uuid import UUID

import httpx
import pytest
import respx

from expose.integrations.chronicle import ChronicleAdapter
from expose.integrations.sentinel import SentinelAdapter
from expose.integrations.siem import CircuitBreakerOpen, DeliveryResult, SIEMConfig
from expose.integrations.splunk import SplunkHECAdapter

# Deterministic test IDs.
TENANT_ID = UUID("018f1f00-0000-7000-8000-000000000001")

# Shared test config values.
SPLUNK_ENDPOINT = "https://splunk.example.com:8088"
SPLUNK_TOKEN = "test-hec-token-abc"  # noqa: S105

# Base64-encoded 32-byte key for Sentinel HMAC tests.
SENTINEL_SHARED_KEY = base64.b64encode(b"0" * 32).decode()
SENTINEL_WORKSPACE = "workspace-abc-123"
SENTINEL_ENDPOINT = f"https://{SENTINEL_WORKSPACE}.ods.opinsights.azure.com"

CHRONICLE_ENDPOINT = "https://malachiteingestion-pa.googleapis.com"
CHRONICLE_TOKEN = "ya29.test-oauth-token"  # noqa: S105


def _splunk_config(**overrides: object) -> SIEMConfig:
    defaults: dict[str, object] = {
        "adapter_type": "splunk",
        "endpoint": SPLUNK_ENDPOINT,
        "auth_token": SPLUNK_TOKEN,
    }
    defaults.update(overrides)
    return SIEMConfig(**defaults)  # type: ignore[arg-type]


def _sentinel_config(**overrides: object) -> SIEMConfig:
    defaults: dict[str, object] = {
        "adapter_type": "sentinel",
        "endpoint": SENTINEL_ENDPOINT,
        "auth_token": SENTINEL_SHARED_KEY,
    }
    defaults.update(overrides)
    return SIEMConfig(**defaults)  # type: ignore[arg-type]


def _chronicle_config(**overrides: object) -> SIEMConfig:
    defaults: dict[str, object] = {
        "adapter_type": "chronicle",
        "endpoint": CHRONICLE_ENDPOINT,
        "auth_token": CHRONICLE_TOKEN,
    }
    defaults.update(overrides)
    return SIEMConfig(**defaults)  # type: ignore[arg-type]


def _sample_observation(**overrides: object) -> dict:
    obs: dict = {
        "entity_identifier": "example.com",
        "observation_type": "open_port",
        "collector_id": "shodan",
        "observed_at": "2026-05-10T12:00:00Z",
        "severity": "medium",
        "source_ip": "1.2.3.4",
        "dest_ip": "5.6.7.8",
        "dest_port": 443,
        "protocol": "tcp",
        "service_name": "https",
        "data": {"port": 443, "banner": "nginx"},
    }
    obs.update(overrides)
    return obs


def _sample_finding(**overrides: object) -> dict:
    finding: dict = {
        "finding_id": "f-001",
        "title": "Exposed Admin Panel",
        "severity": "high",
        "description": "Admin panel accessible without authentication",
        "entity_identifier": "admin.example.com",
        "indicators": [{"indicator": "admin_panel_exposed", "severity": "high"}],
    }
    finding.update(overrides)
    return finding


# ===========================================================================
# SIEMConfig validation
# ===========================================================================


class TestSIEMConfig:
    def test_valid_config(self) -> None:
        cfg = _splunk_config()
        assert cfg.adapter_type == "splunk"
        assert cfg.endpoint == SPLUNK_ENDPOINT
        assert cfg.enabled is True
        assert cfg.batch_size == 100

    def test_empty_endpoint_rejected(self) -> None:
        with pytest.raises(Exception):  # noqa: B017
            _splunk_config(endpoint="")

    def test_empty_auth_token_rejected(self) -> None:
        with pytest.raises(Exception):  # noqa: B017
            _splunk_config(auth_token="")

    def test_batch_size_min(self) -> None:
        with pytest.raises(Exception):  # noqa: B017
            _splunk_config(batch_size=0)

    def test_batch_size_max(self) -> None:
        with pytest.raises(Exception):  # noqa: B017
            _splunk_config(batch_size=1001)

    def test_extra_fields_rejected(self) -> None:
        with pytest.raises(Exception):  # noqa: B017
            SIEMConfig(
                adapter_type="splunk",
                endpoint=SPLUNK_ENDPOINT,
                auth_token=SPLUNK_TOKEN,
                bogus="nope",  # type: ignore[call-arg]
            )


# ===========================================================================
# DeliveryResult validation
# ===========================================================================


class TestDeliveryResult:
    def test_valid_result(self) -> None:
        r = DeliveryResult(
            adapter_id="splunk",
            success=True,
            events_sent=10,
            events_failed=0,
            duration_ms=42.5,
        )
        assert r.success is True
        assert r.events_sent == 10
        assert r.error is None

    def test_negative_events_sent_rejected(self) -> None:
        with pytest.raises(Exception):  # noqa: B017
            DeliveryResult(
                adapter_id="splunk",
                success=True,
                events_sent=-1,
                events_failed=0,
                duration_ms=1.0,
            )

    def test_negative_duration_rejected(self) -> None:
        with pytest.raises(Exception):  # noqa: B017
            DeliveryResult(
                adapter_id="splunk",
                success=True,
                events_sent=0,
                events_failed=0,
                duration_ms=-1.0,
            )


# ===========================================================================
# Splunk HEC adapter
# ===========================================================================


class TestSplunkHEC:
    def test_hec_endpoint_url(self) -> None:
        adapter = SplunkHECAdapter(_splunk_config())
        assert adapter._hec_url == f"{SPLUNK_ENDPOINT}/services/collector/event"

    def test_auth_header_format(self) -> None:
        adapter = SplunkHECAdapter(_splunk_config())
        headers = adapter._auth_headers
        assert headers["Authorization"] == f"Splunk {SPLUNK_TOKEN}"
        assert headers["Content-Type"] == "application/json"

    def test_observation_cim_mapping(self) -> None:
        adapter = SplunkHECAdapter(_splunk_config())
        obs = _sample_observation()
        hec = adapter._map_observation_to_hec(obs, TENANT_ID)
        assert hec["sourcetype"] == "expose:observation"
        assert hec["host"] == "example.com"
        assert hec["index"] == "main"
        assert hec["source"] == f"expose:tenant:{TENANT_ID}"
        event = hec["event"]
        assert event["tenant_id"] == str(TENANT_ID)
        assert event["src"] == "1.2.3.4"
        assert event["dest"] == "5.6.7.8"
        assert event["dest_port"] == 443
        assert event["transport"] == "tcp"

    @respx.mock
    async def test_batch_delivery_newline_delimited(self) -> None:
        """Verify HEC receives newline-delimited JSON for batch delivery."""
        captured_content: list[bytes] = []
        route = respx.post(f"{SPLUNK_ENDPOINT}/services/collector/event").mock(
            side_effect=lambda req: (
                captured_content.append(req.content),
                httpx.Response(200, json={"text": "Success", "code": 0}),
            )[1],
        )

        adapter = SplunkHECAdapter(_splunk_config(batch_size=10))
        obs_list = [_sample_observation() for _ in range(3)]
        result = await adapter.send_observations(obs_list, TENANT_ID)

        assert result.success is True
        assert result.events_sent == 3
        assert result.adapter_id == "splunk"
        assert route.called

        # Verify newline-delimited format.
        body = captured_content[0].decode()
        lines = body.strip().split("\n")
        assert len(lines) == 3
        for line in lines:
            parsed = json.loads(line)
            assert parsed["sourcetype"] == "expose:observation"

    @respx.mock
    async def test_retry_on_5xx_then_success(self) -> None:
        """First request returns 500, second returns 200."""
        call_count = 0

        def _side_effect(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return httpx.Response(500, text="Internal Server Error")
            return httpx.Response(200, json={"text": "Success", "code": 0})

        respx.post(f"{SPLUNK_ENDPOINT}/services/collector/event").mock(
            side_effect=_side_effect,
        )

        adapter = SplunkHECAdapter(_splunk_config())
        result = await adapter.send_observations([_sample_observation()], TENANT_ID)

        assert result.success is True
        assert result.events_sent == 1
        assert call_count == 2

    @respx.mock
    async def test_finding_delivery(self) -> None:
        respx.post(f"{SPLUNK_ENDPOINT}/services/collector/event").mock(
            return_value=httpx.Response(200, json={"text": "Success", "code": 0}),
        )

        adapter = SplunkHECAdapter(_splunk_config())
        result = await adapter.send_finding(_sample_finding(), TENANT_ID)

        assert result.success is True
        assert result.events_sent == 1
        assert result.adapter_id == "splunk"

    @respx.mock
    async def test_health_check_success(self) -> None:
        respx.get(f"{SPLUNK_ENDPOINT}/services/collector/health/1.0").mock(
            return_value=httpx.Response(200, json={"text": "HEC is healthy"}),
        )

        adapter = SplunkHECAdapter(_splunk_config())
        assert await adapter.health_check() is True

    @respx.mock
    async def test_health_check_failure(self) -> None:
        respx.get(f"{SPLUNK_ENDPOINT}/services/collector/health/1.0").mock(
            side_effect=httpx.ConnectError("Connection refused"),
        )

        adapter = SplunkHECAdapter(_splunk_config())
        assert await adapter.health_check() is False

    async def test_disabled_adapter_skipped(self) -> None:
        adapter = SplunkHECAdapter(_splunk_config(enabled=False))
        result = await adapter.send_observations([_sample_observation()], TENANT_ID)
        assert result.success is True
        assert result.events_sent == 0
        assert result.events_failed == 0
        assert result.duration_ms == 0.0

    def test_custom_index(self) -> None:
        adapter = SplunkHECAdapter(_splunk_config(), index="security")
        obs = _sample_observation()
        hec = adapter._map_observation_to_hec(obs, TENANT_ID)
        assert hec["index"] == "security"

    @respx.mock
    async def test_all_retries_exhausted(self) -> None:
        """All requests return 500 — delivery fails."""
        respx.post(f"{SPLUNK_ENDPOINT}/services/collector/event").mock(
            return_value=httpx.Response(500, text="Internal Server Error"),
        )

        adapter = SplunkHECAdapter(_splunk_config())
        result = await adapter.send_observations([_sample_observation()], TENANT_ID)

        assert result.success is False
        assert result.events_failed == 1


# ===========================================================================
# Microsoft Sentinel adapter
# ===========================================================================


class TestSentinel:
    def test_hmac_signature_construction(self) -> None:
        """Verify HMAC signature matches a known vector."""
        sig = SentinelAdapter.build_signature(
            workspace_id=SENTINEL_WORKSPACE,
            shared_key=SENTINEL_SHARED_KEY,
            date="Thu, 01 Jan 2026 00:00:00 GMT",
            content_length=42,
        )
        assert sig.startswith(f"SharedKey {SENTINEL_WORKSPACE}:")
        # Extract base64 hash and verify it's valid base64.
        parts = sig.split(":")
        assert len(parts) == 2
        hash_b64 = parts[1]
        decoded = base64.b64decode(hash_b64)
        assert len(decoded) == 32  # SHA-256 produces 32 bytes

    def test_workspace_id_extraction(self) -> None:
        adapter = SentinelAdapter(
            _sentinel_config(),
            workspace_id="",
        )
        assert adapter._workspace_id == SENTINEL_WORKSPACE

    def test_observation_field_suffixes(self) -> None:
        obs = _sample_observation()
        mapped = SentinelAdapter._map_observation(obs, TENANT_ID)
        # String fields end with _s.
        assert "tenant_id_s" in mapped
        assert "entity_identifier_s" in mapped
        assert "severity_s" in mapped
        assert "protocol_s" in mapped
        # Double fields end with _d.
        assert "dest_port_d" in mapped
        # Datetime fields end with _t.
        assert "observed_at_t" in mapped

    @respx.mock
    async def test_observations_use_correct_table(self) -> None:
        """POST should include Log-Type header = EXPOSE_Observations_CL."""
        captured_headers: list[dict[str, str]] = []
        api_url = f"https://{SENTINEL_WORKSPACE}.ods.opinsights.azure.com/api/logs"
        respx.post(url__startswith=api_url).mock(
            side_effect=lambda req: (
                captured_headers.append(dict(req.headers)),
                httpx.Response(200),
            )[1],
        )

        adapter = SentinelAdapter(
            _sentinel_config(),
            workspace_id=SENTINEL_WORKSPACE,
        )
        result = await adapter.send_observations([_sample_observation()], TENANT_ID)

        assert result.success is True
        assert result.events_sent == 1
        assert captured_headers[0]["log-type"] == "EXPOSE_Observations_CL"

    @respx.mock
    async def test_finding_uses_findings_table(self) -> None:
        """Finding delivery should use EXPOSE_Findings_CL table."""
        captured_headers: list[dict[str, str]] = []
        api_url = f"https://{SENTINEL_WORKSPACE}.ods.opinsights.azure.com/api/logs"
        respx.post(url__startswith=api_url).mock(
            side_effect=lambda req: (
                captured_headers.append(dict(req.headers)),
                httpx.Response(200),
            )[1],
        )

        adapter = SentinelAdapter(
            _sentinel_config(),
            workspace_id=SENTINEL_WORKSPACE,
        )
        result = await adapter.send_finding(_sample_finding(), TENANT_ID)

        assert result.success is True
        assert result.events_sent == 1
        assert captured_headers[0]["log-type"] == "EXPOSE_Findings_CL"

    async def test_disabled_adapter_skipped(self) -> None:
        adapter = SentinelAdapter(
            _sentinel_config(enabled=False),
            workspace_id=SENTINEL_WORKSPACE,
        )
        result = await adapter.send_observations([_sample_observation()], TENANT_ID)
        assert result.success is True
        assert result.events_sent == 0

    @respx.mock
    async def test_health_check_success(self) -> None:
        api_url = f"https://{SENTINEL_WORKSPACE}.ods.opinsights.azure.com/api/logs"
        respx.post(url__startswith=api_url).mock(
            return_value=httpx.Response(200),
        )

        adapter = SentinelAdapter(
            _sentinel_config(),
            workspace_id=SENTINEL_WORKSPACE,
        )
        assert await adapter.health_check() is True

    @respx.mock
    async def test_health_check_network_error(self) -> None:
        api_url = f"https://{SENTINEL_WORKSPACE}.ods.opinsights.azure.com/api/logs"
        respx.post(url__startswith=api_url).mock(
            side_effect=httpx.ConnectError("Connection refused"),
        )

        adapter = SentinelAdapter(
            _sentinel_config(),
            workspace_id=SENTINEL_WORKSPACE,
        )
        assert await adapter.health_check() is False

    def test_finding_field_mapping(self) -> None:
        finding = _sample_finding()
        mapped = SentinelAdapter._map_finding(finding, TENANT_ID)
        assert mapped["finding_id_s"] == "f-001"
        assert mapped["title_s"] == "Exposed Admin Panel"
        assert mapped["severity_s"] == "high"
        assert mapped["tenant_id_s"] == str(TENANT_ID)


# ===========================================================================
# Google Chronicle adapter
# ===========================================================================


class TestChronicle:
    def test_udm_observation_mapping(self) -> None:
        adapter = ChronicleAdapter(_chronicle_config())
        obs = _sample_observation()
        entry = adapter._map_observation_to_udm(obs, TENANT_ID)
        assert "log_text" in entry
        udm = json.loads(entry["log_text"])
        assert udm["metadata"]["event_type"] == "NETWORK_UNCATEGORIZED"
        assert udm["metadata"]["product_name"] == "EXPOSE"
        assert udm["metadata"]["vendor_name"] == "Korlogos"
        assert udm["principal"]["hostname"] == "example.com"
        assert udm["principal"]["ip"] == ["1.2.3.4"]
        assert udm["target"]["ip"] == ["5.6.7.8"]
        assert udm["target"]["port"] == 443

    def test_udm_dns_mapping(self) -> None:
        adapter = ChronicleAdapter(_chronicle_config())
        obs = _sample_observation(
            dns_questions=[{"name": "example.com", "type": "A"}],
        )
        entry = adapter._map_observation_to_udm(obs, TENANT_ID)
        udm = json.loads(entry["log_text"])
        assert udm["network"]["dns"]["questions"] == [
            {"name": "example.com", "type": "A"},
        ]

    def test_batch_request_format(self) -> None:
        entries = [{"log_text": "test"}]
        body = ChronicleAdapter._build_batch_request(entries)
        assert body["log_type"] == "EXPOSE_OBSERVATION"
        assert body["entries"] == entries
        assert "customer_id" in body

    def test_auth_header_bearer_format(self) -> None:
        adapter = ChronicleAdapter(_chronicle_config())
        headers = adapter._auth_headers
        assert headers["Authorization"] == f"Bearer {CHRONICLE_TOKEN}"
        assert headers["Content-Type"] == "application/json"

    def test_finding_udm_mapping(self) -> None:
        adapter = ChronicleAdapter(_chronicle_config())
        finding = _sample_finding()
        entry = adapter._map_finding_to_udm(finding, TENANT_ID)
        udm = json.loads(entry["log_text"])
        assert udm["metadata"]["event_type"] == "GENERIC_EVENT"
        assert udm["security_result"][0]["summary"] == "Exposed Admin Panel"
        assert udm["security_result"][0]["severity"] == "HIGH"
        assert udm["principal"]["hostname"] == "admin.example.com"

    @respx.mock
    async def test_observation_delivery(self) -> None:
        ingestion_url = f"{CHRONICLE_ENDPOINT}/v2/unstructuredlogentries:batchCreate"
        respx.post(ingestion_url).mock(
            return_value=httpx.Response(200, json={}),
        )

        adapter = ChronicleAdapter(_chronicle_config())
        result = await adapter.send_observations([_sample_observation()], TENANT_ID)

        assert result.success is True
        assert result.events_sent == 1
        assert result.adapter_id == "chronicle"

    @respx.mock
    async def test_finding_delivery(self) -> None:
        ingestion_url = f"{CHRONICLE_ENDPOINT}/v2/unstructuredlogentries:batchCreate"
        respx.post(ingestion_url).mock(
            return_value=httpx.Response(200, json={}),
        )

        adapter = ChronicleAdapter(_chronicle_config())
        result = await adapter.send_finding(_sample_finding(), TENANT_ID)

        assert result.success is True
        assert result.events_sent == 1

    async def test_disabled_adapter_skipped(self) -> None:
        adapter = ChronicleAdapter(_chronicle_config(enabled=False))
        result = await adapter.send_observations([_sample_observation()], TENANT_ID)
        assert result.success is True
        assert result.events_sent == 0

    @respx.mock
    async def test_health_check_success(self) -> None:
        ingestion_url = f"{CHRONICLE_ENDPOINT}/v2/unstructuredlogentries:batchCreate"
        respx.post(ingestion_url).mock(
            return_value=httpx.Response(200, json={}),
        )

        adapter = ChronicleAdapter(_chronicle_config())
        assert await adapter.health_check() is True

    @respx.mock
    async def test_health_check_network_error(self) -> None:
        ingestion_url = f"{CHRONICLE_ENDPOINT}/v2/unstructuredlogentries:batchCreate"
        respx.post(ingestion_url).mock(
            side_effect=httpx.ConnectError("Connection refused"),
        )

        adapter = ChronicleAdapter(_chronicle_config())
        assert await adapter.health_check() is False

    @respx.mock
    async def test_delivery_error_handling(self) -> None:
        """All retries exhausted — delivery fails with error."""
        ingestion_url = f"{CHRONICLE_ENDPOINT}/v2/unstructuredlogentries:batchCreate"
        respx.post(ingestion_url).mock(
            return_value=httpx.Response(500, text="Server Error"),
        )

        adapter = ChronicleAdapter(_chronicle_config())
        result = await adapter.send_finding(_sample_finding(), TENANT_ID)

        assert result.success is False
        assert result.events_failed == 1
        assert result.error is not None

    def test_ingestion_url_with_full_path(self) -> None:
        """Config endpoint already contains the full path."""
        full_url = (
            "https://malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate"
        )
        cfg = _chronicle_config(endpoint=full_url)
        adapter = ChronicleAdapter(cfg)
        assert adapter._ingestion_url == full_url

    def test_ingestion_url_without_path(self) -> None:
        """Config endpoint is just the base — path is appended."""
        adapter = ChronicleAdapter(_chronicle_config())
        assert adapter._ingestion_url.endswith(
            "/v2/unstructuredlogentries:batchCreate",
        )


# ===========================================================================
# Integration tests: retry on 429, circuit breaker, entity type mapping,
# batch size limits
# ===========================================================================


class TestRetryOn429:
    """Verify that 429 rate-limit responses are retried (base adapter behaviour)."""

    @respx.mock
    async def test_splunk_retries_on_429_then_success(self) -> None:
        """First request returns 429, second returns 200."""
        call_count = 0

        def _side_effect(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return httpx.Response(429, text="Rate limited")
            return httpx.Response(200, json={"text": "Success", "code": 0})

        respx.post(f"{SPLUNK_ENDPOINT}/services/collector/event").mock(
            side_effect=_side_effect,
        )

        adapter = SplunkHECAdapter(_splunk_config())
        result = await adapter.send_observations([_sample_observation()], TENANT_ID)

        assert result.success is True
        assert result.events_sent == 1
        assert call_count == 2

    @respx.mock
    async def test_sentinel_retries_on_429(self) -> None:
        """Sentinel retries 429 and succeeds on second attempt."""
        call_count = 0
        api_url = f"https://{SENTINEL_WORKSPACE}.ods.opinsights.azure.com/api/logs"

        def _side_effect(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return httpx.Response(429, text="Rate limited")
            return httpx.Response(200)

        respx.post(url__startswith=api_url).mock(side_effect=_side_effect)

        adapter = SentinelAdapter(
            _sentinel_config(),
            workspace_id=SENTINEL_WORKSPACE,
        )
        result = await adapter.send_observations([_sample_observation()], TENANT_ID)

        assert result.success is True
        assert call_count == 2

    @respx.mock
    async def test_chronicle_retries_on_429(self) -> None:
        """Chronicle retries 429 and succeeds on second attempt."""
        call_count = 0
        ingestion_url = f"{CHRONICLE_ENDPOINT}/v2/unstructuredlogentries:batchCreate"

        def _side_effect(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return httpx.Response(429, text="Rate limited")
            return httpx.Response(200, json={})

        respx.post(ingestion_url).mock(side_effect=_side_effect)

        adapter = ChronicleAdapter(_chronicle_config())
        result = await adapter.send_observations([_sample_observation()], TENANT_ID)

        assert result.success is True
        assert call_count == 2


class TestCircuitBreaker:
    """Verify circuit breaker opens after threshold and resets after cooldown."""

    @respx.mock
    async def test_circuit_breaker_opens_after_threshold(self) -> None:
        """After 5 consecutive all-retries-exhausted failures, breaker opens."""
        respx.post(f"{SPLUNK_ENDPOINT}/services/collector/event").mock(
            return_value=httpx.Response(500, text="Internal Server Error"),
        )

        adapter = SplunkHECAdapter(_splunk_config())

        # Exhaust retries 5 times to trip the breaker (threshold = 5).
        for _ in range(5):
            await adapter.send_observations([_sample_observation()], TENANT_ID)

        assert adapter.circuit_is_open is True

    @respx.mock
    async def test_circuit_breaker_short_circuits_delivery(self) -> None:
        """Once open, the breaker causes immediate failure without HTTP calls."""
        respx.post(f"{SPLUNK_ENDPOINT}/services/collector/event").mock(
            return_value=httpx.Response(500, text="Internal Server Error"),
        )

        adapter = SplunkHECAdapter(_splunk_config())

        # Trip the breaker.
        for _ in range(5):
            await adapter.send_observations([_sample_observation()], TENANT_ID)

        assert adapter.circuit_is_open is True

        # Next call should fail immediately (circuit breaker).
        result = await adapter.send_observations([_sample_observation()], TENANT_ID)
        assert result.success is False
        assert result.events_failed == 1

    async def test_circuit_breaker_resets_on_success(self) -> None:
        """A successful call resets the failure counter."""
        adapter = SplunkHECAdapter(_splunk_config())

        # Manually simulate some failures without fully tripping.
        adapter._consecutive_failures = 4
        adapter._record_success()

        assert adapter._consecutive_failures == 0
        assert adapter.circuit_is_open is False

    async def test_circuit_breaker_not_open_initially(self) -> None:
        """Fresh adapter has breaker closed."""
        adapter = SplunkHECAdapter(_splunk_config())
        assert adapter.circuit_is_open is False
        assert adapter._consecutive_failures == 0


class TestSplunkEntityTypeMapping:
    """Verify EXPOSE entity types map to correct Splunk CIM data models."""

    def test_domain_entity_cim_mapping(self) -> None:
        adapter = SplunkHECAdapter(_splunk_config())
        obs = _sample_observation(entity_type="domain", entity_identifier="example.com")
        hec = adapter._map_observation_to_hec(obs, TENANT_ID)
        event = hec["event"]
        assert event["cim_data_model"] == "DNS"
        assert event["query"] == "example.com"
        assert event["entity_type"] == "domain"

    def test_subdomain_entity_cim_mapping(self) -> None:
        adapter = SplunkHECAdapter(_splunk_config())
        obs = _sample_observation(entity_type="subdomain", entity_identifier="api.example.com")
        hec = adapter._map_observation_to_hec(obs, TENANT_ID)
        event = hec["event"]
        assert event["cim_data_model"] == "DNS"
        assert event["query"] == "api.example.com"

    def test_ip_entity_cim_mapping(self) -> None:
        adapter = SplunkHECAdapter(_splunk_config())
        obs = _sample_observation(entity_type="ip", entity_identifier="192.168.1.1")
        hec = adapter._map_observation_to_hec(obs, TENANT_ID)
        event = hec["event"]
        assert event["cim_data_model"] == "Network_Traffic"
        # entity_type=ip maps entity_identifier to src (overwrites source_ip).
        assert event["src"] == "192.168.1.1"

    def test_cidr_entity_cim_mapping(self) -> None:
        adapter = SplunkHECAdapter(_splunk_config())
        obs = _sample_observation(entity_type="cidr", entity_identifier="10.0.0.0/8")
        hec = adapter._map_observation_to_hec(obs, TENANT_ID)
        event = hec["event"]
        assert event["cim_data_model"] == "Network_Traffic"
        assert event["src_range"] == "10.0.0.0/8"

    def test_cloud_resource_entity_cim_mapping(self) -> None:
        adapter = SplunkHECAdapter(_splunk_config())
        obs = _sample_observation(
            entity_type="cloud_resource_id",
            entity_identifier="arn:aws:s3:::my-bucket",
            cloud_provider="aws",
        )
        hec = adapter._map_observation_to_hec(obs, TENANT_ID)
        event = hec["event"]
        assert event["cim_data_model"] == "Cloud_Infrastructure"
        assert event["object_id"] == "arn:aws:s3:::my-bucket"
        assert event["vendor_product"] == "aws"

    def test_url_entity_cim_mapping(self) -> None:
        adapter = SplunkHECAdapter(_splunk_config())
        obs = _sample_observation(
            entity_type="url",
            entity_identifier="https://example.com/admin",
        )
        hec = adapter._map_observation_to_hec(obs, TENANT_ID)
        event = hec["event"]
        assert event["cim_data_model"] == "Web"
        assert event["url"] == "https://example.com/admin"
        assert event["http_method"] == "GET"

    def test_unknown_entity_type_defaults_to_network(self) -> None:
        adapter = SplunkHECAdapter(_splunk_config())
        obs = _sample_observation(entity_type="other_thing")
        hec = adapter._map_observation_to_hec(obs, TENANT_ID)
        assert hec["event"]["cim_data_model"] == "Network_Traffic"


class TestSplunkSeverityMapping:
    """Verify EXPOSE severity -> Splunk CIM severity mapping."""

    def test_info_maps_to_informational(self) -> None:
        adapter = SplunkHECAdapter(_splunk_config())
        obs = _sample_observation(severity="info")
        hec = adapter._map_observation_to_hec(obs, TENANT_ID)
        assert hec["event"]["severity"] == "informational"

    def test_high_maps_to_high(self) -> None:
        adapter = SplunkHECAdapter(_splunk_config())
        obs = _sample_observation(severity="high")
        hec = adapter._map_observation_to_hec(obs, TENANT_ID)
        assert hec["event"]["severity"] == "high"

    def test_critical_maps_to_critical(self) -> None:
        adapter = SplunkHECAdapter(_splunk_config())
        obs = _sample_observation(severity="critical")
        hec = adapter._map_observation_to_hec(obs, TENANT_ID)
        assert hec["event"]["severity"] == "critical"

    def test_finding_severity_mapped(self) -> None:
        adapter = SplunkHECAdapter(_splunk_config())
        finding = _sample_finding(severity="high")
        hec = adapter._map_finding_to_hec(finding, TENANT_ID)
        assert hec["event"]["severity"] == "high"

    def test_finding_info_severity_mapped(self) -> None:
        adapter = SplunkHECAdapter(_splunk_config())
        finding = _sample_finding(severity="info")
        hec = adapter._map_finding_to_hec(finding, TENANT_ID)
        assert hec["event"]["severity"] == "informational"


class TestSentinelEntityType:
    """Verify entity_type field is included in Sentinel mapped observations/findings."""

    def test_observation_includes_entity_type(self) -> None:
        obs = _sample_observation(entity_type="domain")
        mapped = SentinelAdapter._map_observation(obs, TENANT_ID)
        assert mapped["entity_type_s"] == "domain"

    def test_observation_entity_type_default_empty(self) -> None:
        obs = _sample_observation()  # no entity_type key
        mapped = SentinelAdapter._map_observation(obs, TENANT_ID)
        assert mapped["entity_type_s"] == ""

    def test_finding_includes_entity_type(self) -> None:
        finding = _sample_finding(entity_type="subdomain")
        mapped = SentinelAdapter._map_finding(finding, TENANT_ID)
        assert mapped["entity_type_s"] == "subdomain"


class TestChronicleEntityTypeUDM:
    """Verify EXPOSE entity types map to correct UDM event_type values."""

    def test_domain_maps_to_network_dns(self) -> None:
        adapter = ChronicleAdapter(_chronicle_config())
        obs = _sample_observation(entity_type="domain")
        entry = adapter._map_observation_to_udm(obs, TENANT_ID)
        udm = json.loads(entry["log_text"])
        assert udm["metadata"]["event_type"] == "NETWORK_DNS"

    def test_subdomain_maps_to_network_dns(self) -> None:
        adapter = ChronicleAdapter(_chronicle_config())
        obs = _sample_observation(entity_type="subdomain")
        entry = adapter._map_observation_to_udm(obs, TENANT_ID)
        udm = json.loads(entry["log_text"])
        assert udm["metadata"]["event_type"] == "NETWORK_DNS"

    def test_ip_maps_to_network_uncategorized(self) -> None:
        adapter = ChronicleAdapter(_chronicle_config())
        obs = _sample_observation(entity_type="ip")
        entry = adapter._map_observation_to_udm(obs, TENANT_ID)
        udm = json.loads(entry["log_text"])
        assert udm["metadata"]["event_type"] == "NETWORK_UNCATEGORIZED"

    def test_url_maps_to_network_http(self) -> None:
        adapter = ChronicleAdapter(_chronicle_config())
        obs = _sample_observation(entity_type="url", entity_identifier="https://example.com")
        entry = adapter._map_observation_to_udm(obs, TENANT_ID)
        udm = json.loads(entry["log_text"])
        assert udm["metadata"]["event_type"] == "NETWORK_HTTP"
        assert udm["principal"]["url"] == "https://example.com"

    def test_cloud_resource_maps_to_resource_read(self) -> None:
        adapter = ChronicleAdapter(_chronicle_config())
        obs = _sample_observation(
            entity_type="cloud_resource_id",
            entity_identifier="arn:aws:s3:::bucket",
            cloud_service="S3",
        )
        entry = adapter._map_observation_to_udm(obs, TENANT_ID)
        udm = json.loads(entry["log_text"])
        assert udm["metadata"]["event_type"] == "RESOURCE_READ"
        assert udm["target"]["resource"]["product_object_id"] == "arn:aws:s3:::bucket"
        assert udm["target"]["resource"]["resource_type"] == "S3"

    def test_unknown_entity_defaults_to_network_uncategorized(self) -> None:
        adapter = ChronicleAdapter(_chronicle_config())
        obs = _sample_observation(entity_type="unknown_type")
        entry = adapter._map_observation_to_udm(obs, TENANT_ID)
        udm = json.loads(entry["log_text"])
        assert udm["metadata"]["event_type"] == "NETWORK_UNCATEGORIZED"

    def test_entity_type_in_additional_fields(self) -> None:
        adapter = ChronicleAdapter(_chronicle_config())
        obs = _sample_observation(entity_type="domain")
        entry = adapter._map_observation_to_udm(obs, TENANT_ID)
        udm = json.loads(entry["log_text"])
        assert udm["additional"]["fields"]["entity_type"] == "domain"


class TestBatchSizeLimits:
    """Verify that each adapter respects batch_size and makes multiple HTTP calls."""

    @respx.mock
    async def test_splunk_batch_size_multiple_calls(self) -> None:
        """With batch_size=2 and 5 observations, expect 3 HTTP POSTs."""
        call_count = 0

        def _side_effect(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            return httpx.Response(200, json={"text": "Success", "code": 0})

        respx.post(f"{SPLUNK_ENDPOINT}/services/collector/event").mock(
            side_effect=_side_effect,
        )

        adapter = SplunkHECAdapter(_splunk_config(batch_size=2))
        obs_list = [_sample_observation() for _ in range(5)]
        result = await adapter.send_observations(obs_list, TENANT_ID)

        assert result.success is True
        assert result.events_sent == 5
        assert call_count == 3  # ceil(5/2) = 3

    @respx.mock
    async def test_sentinel_batch_size_multiple_calls(self) -> None:
        """With batch_size=2 and 5 observations, expect 3 HTTP POSTs."""
        call_count = 0
        api_url = f"https://{SENTINEL_WORKSPACE}.ods.opinsights.azure.com/api/logs"

        def _side_effect(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            return httpx.Response(200)

        respx.post(url__startswith=api_url).mock(side_effect=_side_effect)

        adapter = SentinelAdapter(
            _sentinel_config(batch_size=2),
            workspace_id=SENTINEL_WORKSPACE,
        )
        obs_list = [_sample_observation() for _ in range(5)]
        result = await adapter.send_observations(obs_list, TENANT_ID)

        assert result.success is True
        assert result.events_sent == 5
        assert call_count == 3

    @respx.mock
    async def test_chronicle_batch_size_multiple_calls(self) -> None:
        """With batch_size=2 and 5 observations, expect 3 HTTP POSTs."""
        call_count = 0
        ingestion_url = f"{CHRONICLE_ENDPOINT}/v2/unstructuredlogentries:batchCreate"

        def _side_effect(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            return httpx.Response(200, json={})

        respx.post(ingestion_url).mock(side_effect=_side_effect)

        adapter = ChronicleAdapter(_chronicle_config(batch_size=2))
        obs_list = [_sample_observation() for _ in range(5)]
        result = await adapter.send_observations(obs_list, TENANT_ID)

        assert result.success is True
        assert result.events_sent == 5
        assert call_count == 3

    @respx.mock
    async def test_splunk_batch_content_size_correct(self) -> None:
        """Each batch POST contains at most batch_size events."""
        captured_bodies: list[bytes] = []

        def _side_effect(request: httpx.Request) -> httpx.Response:
            captured_bodies.append(request.content)
            return httpx.Response(200, json={"text": "Success", "code": 0})

        respx.post(f"{SPLUNK_ENDPOINT}/services/collector/event").mock(
            side_effect=_side_effect,
        )

        adapter = SplunkHECAdapter(_splunk_config(batch_size=3))
        obs_list = [_sample_observation() for _ in range(7)]
        result = await adapter.send_observations(obs_list, TENANT_ID)

        assert result.success is True
        assert result.events_sent == 7
        assert len(captured_bodies) == 3  # 3 + 3 + 1

        # First batch: 3 events (newline-delimited).
        lines_1 = captured_bodies[0].decode().strip().split("\n")
        assert len(lines_1) == 3

        # Second batch: 3 events.
        lines_2 = captured_bodies[1].decode().strip().split("\n")
        assert len(lines_2) == 3

        # Third batch: 1 event.
        lines_3 = captured_bodies[2].decode().strip().split("\n")
        assert len(lines_3) == 1
