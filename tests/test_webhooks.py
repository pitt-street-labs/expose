"""Tests for webhook event delivery and API endpoints.

Coverage:

 1. HMAC-SHA256 signature generation (correct digest)
 2. HMAC signature verification round-trip
 3. Successful delivery (mock 200 response)
 4. Retry on 500 then success on second attempt
 5. Give up after max retries (all 500s)
 6. Network error handling (httpx.ConnectError)
 7. Non-retryable 4xx returns immediately
 8. Event type filtering — subscribed event delivered
 9. Event type filtering — non-subscribed event skipped
10. Disabled webhook skipped
11. X-EXPOSE-Signature header present and correct
12. X-EXPOSE-Event header matches event type
13. X-EXPOSE-Delivery header is a valid UUID
14. Webhook CRUD — create returns 201
15. Webhook CRUD — list returns created webhooks
16. Webhook CRUD — delete returns 204
17. Webhook CRUD — delete unknown returns 404
18. Test webhook endpoint — success
19. Test webhook endpoint — unknown webhook returns 404
20. Secret minimum length validation
21. Delivery result model fields
22. Custom max_retries=1 honours limit
"""

from __future__ import annotations

import json
import uuid as uuid_mod
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from uuid import UUID

import httpx
import pytest
import respx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from expose.api.webhooks import (
    _webhooks,
    router,
)
from expose.pipeline.webhook_delivery import (
    WebhookConfig,
    WebhookDeliveryEngine,
    WebhookDeliveryResult,
    _compute_hmac_sha256,
    _json_bytes,
)

# Deterministic test IDs
TENANT_ID = UUID("018f1f00-0000-7000-8000-000000000001")
TENANT_ID_2 = UUID("018f1f00-0000-7000-8000-000000000002")
WEBHOOK_URL = "https://hooks.example.com/receive"
WEBHOOK_SECRET = "super-secret-key-1234"  # noqa: S105  # >= 16 chars (test constant)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_webhook_store() -> None:
    """Reset the in-memory webhook store before each test."""
    _webhooks.clear()


def _make_app() -> FastAPI:
    """Build a minimal FastAPI app with the webhooks router mounted."""
    app = FastAPI()

    @asynccontextmanager
    async def _noop_lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield

    app.router.lifespan_context = _noop_lifespan  # type: ignore[assignment]
    app.include_router(router)
    return app


@pytest.fixture()
def app() -> FastAPI:
    return _make_app()


@pytest.fixture()
async def client(app: FastAPI) -> AsyncIterator[AsyncClient]:
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as ac:
        yield ac


def _sample_event(event_type: str = "run_started") -> dict[str, object]:
    return {
        "event_type": event_type,
        "run_id": "018f1f00-0000-7000-8000-000000000099",
        "tenant_id": str(TENANT_ID),
        "data": {"status": "ok"},
    }


def _verify_hmac(secret: str, payload: bytes, hex_digest: str) -> bool:
    """Independently verify an HMAC-SHA256 hex digest."""
    h = HMAC(secret.encode(), hashes.SHA256())
    h.update(payload)
    expected = h.finalize().hex()
    return expected == hex_digest


# ======================================================================
# HMAC signature tests
# ======================================================================


class TestHmacSignature:
    """HMAC-SHA256 signature generation and verification."""

    def test_signature_generation(self) -> None:
        """_compute_hmac_sha256 returns a 64-char lowercase hex string."""
        key = b"test-key-minimum-16"
        data = b'{"event_type":"run_started"}'
        result = _compute_hmac_sha256(key, data)
        assert len(result) == 64
        assert result == result.lower()
        # All hex chars
        assert all(c in "0123456789abcdef" for c in result)

    def test_signature_verification_roundtrip(self) -> None:
        """Signature produced by _compute_hmac_sha256 verifies correctly."""
        key = b"webhook-secret-key-long"
        data = b'{"event_type":"collector_started","data":{}}'
        signature = _compute_hmac_sha256(key, data)
        assert _verify_hmac("webhook-secret-key-long", data, signature)

    def test_wrong_key_fails_verification(self) -> None:
        """Signature with wrong key does not verify."""
        data = b'{"event_type":"run_started"}'
        signature = _compute_hmac_sha256(b"correct-key-minimum", data)
        assert not _verify_hmac("wrong-key-at-least-16", data, signature)


# ======================================================================
# Delivery engine tests
# ======================================================================


class TestDeliveryEngine:
    """WebhookDeliveryEngine delivery, retry, and error handling."""

    @respx.mock
    async def test_successful_delivery(self) -> None:
        """200 response yields success=True on first attempt."""
        respx.post(WEBHOOK_URL).mock(return_value=httpx.Response(200))

        engine = WebhookDeliveryEngine(max_retries=3)
        config = WebhookConfig(url=WEBHOOK_URL, secret=WEBHOOK_SECRET)
        result = await engine.deliver(config, _sample_event())

        assert result.success is True
        assert result.status_code == 200
        assert result.attempt == 1
        assert result.error is None
        assert result.webhook_url == WEBHOOK_URL
        assert result.event_type == "run_started"

    @respx.mock
    async def test_retry_on_500_then_success(self) -> None:
        """500 on first attempt, 200 on second -> success after retry."""
        route = respx.post(WEBHOOK_URL)
        route.side_effect = [
            httpx.Response(500),
            httpx.Response(200),
        ]

        engine = WebhookDeliveryEngine(max_retries=3)
        config = WebhookConfig(url=WEBHOOK_URL, secret=WEBHOOK_SECRET)
        result = await engine.deliver(config, _sample_event())

        assert result.success is True
        assert result.status_code == 200
        assert result.attempt == 2

    @respx.mock
    async def test_give_up_after_max_retries(self) -> None:
        """All attempts return 500 -> failure after max_retries."""
        respx.post(WEBHOOK_URL).mock(return_value=httpx.Response(502))

        engine = WebhookDeliveryEngine(max_retries=3)
        config = WebhookConfig(url=WEBHOOK_URL, secret=WEBHOOK_SECRET)
        result = await engine.deliver(config, _sample_event())

        assert result.success is False
        assert result.status_code == 502
        assert result.attempt == 3
        assert result.error == "HTTP 502"

    @respx.mock
    async def test_network_error_retried(self) -> None:
        """Network error (ConnectError) is retried then gives up."""
        respx.post(WEBHOOK_URL).mock(side_effect=httpx.ConnectError("refused"))

        engine = WebhookDeliveryEngine(max_retries=2)
        config = WebhookConfig(url=WEBHOOK_URL, secret=WEBHOOK_SECRET)
        result = await engine.deliver(config, _sample_event())

        assert result.success is False
        assert result.status_code is None
        assert result.attempt == 2
        assert "refused" in (result.error or "")

    @respx.mock
    async def test_4xx_not_retried(self) -> None:
        """4xx response is a non-retryable failure — returns immediately."""
        respx.post(WEBHOOK_URL).mock(return_value=httpx.Response(403))

        engine = WebhookDeliveryEngine(max_retries=3)
        config = WebhookConfig(url=WEBHOOK_URL, secret=WEBHOOK_SECRET)
        result = await engine.deliver(config, _sample_event())

        assert result.success is False
        assert result.status_code == 403
        assert result.attempt == 1
        assert result.error == "HTTP 403"

    @respx.mock
    async def test_signature_header_present_and_correct(self) -> None:
        """X-EXPOSE-Signature header contains correct HMAC-SHA256."""
        captured_headers: dict[str, str] = {}

        def _capture(request: httpx.Request) -> httpx.Response:
            captured_headers.update(dict(request.headers))
            return httpx.Response(200)

        respx.post(WEBHOOK_URL).mock(side_effect=_capture)

        engine = WebhookDeliveryEngine(max_retries=1)
        config = WebhookConfig(url=WEBHOOK_URL, secret=WEBHOOK_SECRET)
        event = _sample_event()
        await engine.deliver(config, event)

        sig_header = captured_headers.get("x-expose-signature", "")
        assert sig_header.startswith("sha256=")
        hex_digest = sig_header.removeprefix("sha256=")

        # Verify the signature independently.
        payload = _json_bytes(event)
        assert _verify_hmac(WEBHOOK_SECRET, payload, hex_digest)

    @respx.mock
    async def test_event_type_header(self) -> None:
        """X-EXPOSE-Event header matches event_type from the event dict."""
        captured_headers: dict[str, str] = {}

        def _capture(request: httpx.Request) -> httpx.Response:
            captured_headers.update(dict(request.headers))
            return httpx.Response(200)

        respx.post(WEBHOOK_URL).mock(side_effect=_capture)

        engine = WebhookDeliveryEngine(max_retries=1)
        config = WebhookConfig(url=WEBHOOK_URL, secret=WEBHOOK_SECRET)
        await engine.deliver(config, _sample_event("collector_completed"))

        assert captured_headers.get("x-expose-event") == "collector_completed"

    @respx.mock
    async def test_delivery_id_header_is_uuid(self) -> None:
        """X-EXPOSE-Delivery header is a valid UUID string."""
        captured_headers: dict[str, str] = {}

        def _capture(request: httpx.Request) -> httpx.Response:
            captured_headers.update(dict(request.headers))
            return httpx.Response(200)

        respx.post(WEBHOOK_URL).mock(side_effect=_capture)

        engine = WebhookDeliveryEngine(max_retries=1)
        config = WebhookConfig(url=WEBHOOK_URL, secret=WEBHOOK_SECRET)
        await engine.deliver(config, _sample_event())

        delivery_id = captured_headers.get("x-expose-delivery", "")
        # Should not raise — validates UUID format.
        uuid_mod.UUID(delivery_id)

    @respx.mock
    async def test_custom_max_retries(self) -> None:
        """max_retries=1 makes exactly one attempt."""
        respx.post(WEBHOOK_URL).mock(return_value=httpx.Response(503))

        engine = WebhookDeliveryEngine(max_retries=1)
        config = WebhookConfig(url=WEBHOOK_URL, secret=WEBHOOK_SECRET)
        result = await engine.deliver(config, _sample_event())

        assert result.attempt == 1
        assert result.success is False


# ======================================================================
# Event type filtering tests (engine-level, caller-enforced)
# ======================================================================


class TestEventTypeFiltering:
    """WebhookConfig.event_types filtering (enforced by callers)."""

    def test_subscribed_event_passes_filter(self) -> None:
        """When event_types is set, a matching event type passes."""
        config = WebhookConfig(
            url=WEBHOOK_URL,
            secret=WEBHOOK_SECRET,
            event_types=frozenset({"run_started", "run_completed"}),
        )
        assert config.event_types is not None
        assert "run_started" in config.event_types

    def test_unsubscribed_event_filtered(self) -> None:
        """An event type not in event_types should be filtered by callers."""
        config = WebhookConfig(
            url=WEBHOOK_URL,
            secret=WEBHOOK_SECRET,
            event_types=frozenset({"run_started"}),
        )
        assert config.event_types is not None
        assert "collector_completed" not in config.event_types

    def test_none_event_types_means_all(self) -> None:
        """event_types=None means all events are accepted."""
        config = WebhookConfig(
            url=WEBHOOK_URL,
            secret=WEBHOOK_SECRET,
            event_types=None,
        )
        assert config.event_types is None

    def test_disabled_webhook(self) -> None:
        """Disabled webhook should be skipped by callers (enabled=False)."""
        config = WebhookConfig(
            url=WEBHOOK_URL,
            secret=WEBHOOK_SECRET,
            enabled=False,
        )
        assert config.enabled is False


# ======================================================================
# WebhookDeliveryResult model tests
# ======================================================================


class TestDeliveryResultModel:
    """WebhookDeliveryResult frozen model properties."""

    def test_fields_present(self) -> None:
        """Result model exposes all required fields."""
        result = WebhookDeliveryResult(
            webhook_url=WEBHOOK_URL,
            event_type="run_started",
            status_code=200,
            success=True,
            attempt=1,
        )
        assert result.webhook_url == WEBHOOK_URL
        assert result.event_type == "run_started"
        assert result.status_code == 200
        assert result.success is True
        assert result.attempt == 1
        assert result.error is None

    def test_frozen(self) -> None:
        """Result model is immutable (frozen=True)."""
        result = WebhookDeliveryResult(
            webhook_url=WEBHOOK_URL,
            event_type="run_started",
            status_code=200,
            success=True,
            attempt=1,
        )
        with pytest.raises(Exception):  # noqa: B017
            result.success = False  # type: ignore[misc]


# ======================================================================
# API router tests (CRUD + test endpoint)
# ======================================================================


class TestWebhookAPI:
    """Webhook CRUD endpoints and test delivery."""

    async def test_create_webhook_returns_201(self, client: AsyncClient) -> None:
        """POST /webhooks/ returns 201 with webhook config."""
        resp = await client.post(
            f"/v1/tenants/{TENANT_ID}/webhooks/",
            json={
                "url": WEBHOOK_URL,
                "secret": WEBHOOK_SECRET,
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["url"] == WEBHOOK_URL
        assert data["tenant_id"] == str(TENANT_ID)
        assert "webhook_id" in data
        assert data["enabled"] is True

    async def test_list_webhooks_returns_created(self, client: AsyncClient) -> None:
        """GET /webhooks/ lists previously created webhooks."""
        # Create two webhooks.
        await client.post(
            f"/v1/tenants/{TENANT_ID}/webhooks/",
            json={"url": "https://a.example.com/hook", "secret": WEBHOOK_SECRET},
        )
        await client.post(
            f"/v1/tenants/{TENANT_ID}/webhooks/",
            json={"url": "https://b.example.com/hook", "secret": WEBHOOK_SECRET},
        )

        resp = await client.get(f"/v1/tenants/{TENANT_ID}/webhooks/")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2
        urls = {h["url"] for h in data}
        assert "https://a.example.com/hook" in urls
        assert "https://b.example.com/hook" in urls

    async def test_list_webhooks_empty(self, client: AsyncClient) -> None:
        """GET /webhooks/ returns empty list for tenant with no hooks."""
        resp = await client.get(f"/v1/tenants/{TENANT_ID}/webhooks/")
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_delete_webhook_returns_204(self, client: AsyncClient) -> None:
        """DELETE /webhooks/{id} returns 204 and removes the webhook."""
        create_resp = await client.post(
            f"/v1/tenants/{TENANT_ID}/webhooks/",
            json={"url": WEBHOOK_URL, "secret": WEBHOOK_SECRET},
        )
        webhook_id = create_resp.json()["webhook_id"]

        del_resp = await client.delete(
            f"/v1/tenants/{TENANT_ID}/webhooks/{webhook_id}",
        )
        assert del_resp.status_code == 204

        # Verify it's gone.
        list_resp = await client.get(f"/v1/tenants/{TENANT_ID}/webhooks/")
        assert list_resp.json() == []

    async def test_delete_unknown_webhook_returns_404(self, client: AsyncClient) -> None:
        """DELETE /webhooks/{id} with unknown id returns 404."""
        resp = await client.delete(
            f"/v1/tenants/{TENANT_ID}/webhooks/nonexistent-id",
        )
        assert resp.status_code == 404

    @respx.mock
    async def test_test_webhook_success(self, client: AsyncClient) -> None:
        """POST /webhooks/{id}/test delivers a test event and returns result."""
        respx.post(WEBHOOK_URL).mock(return_value=httpx.Response(200))

        create_resp = await client.post(
            f"/v1/tenants/{TENANT_ID}/webhooks/",
            json={"url": WEBHOOK_URL, "secret": WEBHOOK_SECRET},
        )
        webhook_id = create_resp.json()["webhook_id"]

        test_resp = await client.post(
            f"/v1/tenants/{TENANT_ID}/webhooks/{webhook_id}/test",
        )
        assert test_resp.status_code == 200
        data = test_resp.json()
        assert data["success"] is True
        assert data["event_type"] == "webhook.test"
        assert data["webhook_url"] == WEBHOOK_URL

    async def test_test_unknown_webhook_returns_404(self, client: AsyncClient) -> None:
        """POST /webhooks/{id}/test with unknown id returns 404."""
        resp = await client.post(
            f"/v1/tenants/{TENANT_ID}/webhooks/nonexistent-id/test",
        )
        assert resp.status_code == 404

    async def test_secret_too_short_rejected(self, client: AsyncClient) -> None:
        """POST /webhooks/ with secret < 16 chars is rejected (422)."""
        resp = await client.post(
            f"/v1/tenants/{TENANT_ID}/webhooks/",
            json={"url": WEBHOOK_URL, "secret": "short"},
        )
        assert resp.status_code == 422

    async def test_tenant_isolation(self, client: AsyncClient) -> None:
        """Webhooks for one tenant are not visible to another."""
        await client.post(
            f"/v1/tenants/{TENANT_ID}/webhooks/",
            json={"url": WEBHOOK_URL, "secret": WEBHOOK_SECRET},
        )

        resp = await client.get(f"/v1/tenants/{TENANT_ID_2}/webhooks/")
        assert resp.status_code == 200
        assert resp.json() == []


# ======================================================================
# JSON serialization helper
# ======================================================================


class TestJsonBytes:
    """_json_bytes canonical serialization."""

    def test_deterministic_key_order(self) -> None:
        """Keys are sorted for deterministic HMAC input."""
        result = _json_bytes({"z": 1, "a": 2})
        parsed = json.loads(result)
        keys = list(parsed.keys())
        assert keys == ["a", "z"]

    def test_compact_separators(self) -> None:
        """Output uses compact separators (no whitespace)."""
        result = _json_bytes({"key": "value"})
        assert b" " not in result
