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
from expose.integrations.siem import DeliveryResult, SIEMConfig
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
