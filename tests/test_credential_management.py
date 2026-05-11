"""Tests for credential management — API router + native bundle import/export.

Covers the full credential lifecycle:

- Listing known credential slots with status (configured/missing)
- Importing credentials from SpiderFoot-style key-value pairs
- Importing credentials from native JSON bundles
- Exporting configured credentials with masked values
- Testing individual credentials (presence check)
- The ``mask_value`` utility function edge cases
- Round-trip: export -> import -> verify same keys
- Error handling for invalid/unknown inputs

The test suite uses the :class:`InMemoryBackend` directly and the FastAPI
``TestClient`` for router-level integration tests.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from expose.api.credentials import (
    _SLOTS_BY_ID,
    KNOWN_SLOTS,
    router,
    set_backend,
)
from expose.import_.credential_bundle import (
    CredentialBundle,
    export_bundle,
    import_bundle,
    mask_value,
)
from expose.secrets.memory_backend import InMemoryBackend

TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000c001")
TENANT_ID_STR = str(TENANT_ID)


@pytest.fixture
def backend() -> InMemoryBackend:
    """Fresh in-memory secrets backend for each test."""
    return InMemoryBackend()


@pytest.fixture
def client(backend: InMemoryBackend) -> TestClient:
    """FastAPI test client with the credentials router mounted."""
    set_backend(backend)
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


# ============================================================================
# mask_value function tests
# ============================================================================


class TestMaskValue:
    """Tests for the mask_value utility function."""

    def test_mask_long_value(self) -> None:
        """Values longer than 4 chars show last 4 after asterisks."""
        assert mask_value("abcdefgh1234") == "****1234"

    def test_mask_exactly_five_chars(self) -> None:
        """Five-char value masks to ****<last-char>... wait, last 4."""
        assert mask_value("abcde") == "****bcde"

    def test_mask_exactly_four_chars(self) -> None:
        """Four-char values are fully masked — revealing all 4 would defeat masking."""
        assert mask_value("abcd") == "****"

    def test_mask_three_chars(self) -> None:
        """Short values are fully masked."""
        assert mask_value("abc") == "****"

    def test_mask_single_char(self) -> None:
        """Single character is fully masked."""
        assert mask_value("x") == "****"

    def test_mask_empty_string(self) -> None:
        """Empty string still produces the mask placeholder."""
        assert mask_value("") == "****"

    def test_mask_typical_api_key(self) -> None:
        """Realistic API key gets properly masked."""
        assert mask_value("sk-proj-abc123def456xyz789") == "****z789"


# ============================================================================
# CredentialBundle model + import/export functions
# ============================================================================


class TestCredentialBundle:
    """Tests for the native credential bundle format."""

    def test_export_bundle_masks_by_default(self) -> None:
        """export_bundle with default mask=True replaces values."""
        secrets = {"shodan_api_key": "SHODAN_KEY_12345678"}
        bundle = export_bundle(secrets, mask=True)
        assert bundle.format_version == "1.0"
        assert bundle.credentials["shodan_api_key"] == "****5678"

    def test_export_bundle_unmasked(self) -> None:
        """export_bundle with mask=False preserves full values."""
        secrets = {"shodan_api_key": "SHODAN_KEY_12345678"}
        bundle = export_bundle(secrets, mask=False)
        assert bundle.credentials["shodan_api_key"] == "SHODAN_KEY_12345678"

    def test_export_bundle_sets_timestamp(self) -> None:
        """exported_at is populated with a UTC timestamp."""
        bundle = export_bundle({"k": "v"})
        assert bundle.exported_at.tzinfo is not None

    def test_import_bundle_extracts_credentials(self) -> None:
        """import_bundle returns the credentials dict from a bundle."""
        bundle = CredentialBundle(
            format_version="1.0",
            exported_at=datetime.now(UTC),
            credentials={"shodan_api_key": "test-key-value"},
        )
        result = import_bundle(bundle)
        assert result == {"shodan_api_key": "test-key-value"}

    def test_import_bundle_preserves_all_keys(self) -> None:
        """All keys from the bundle are returned by import_bundle."""
        creds = {"key_a": "val_a", "key_b": "val_b", "key_c": "val_c"}
        bundle = CredentialBundle(
            format_version="1.0",
            exported_at=datetime.now(UTC),
            credentials=creds,
        )
        result = import_bundle(bundle)
        assert set(result.keys()) == set(creds.keys())

    def test_round_trip_export_import_unmasked(self) -> None:
        """Export (unmasked) -> import -> same credentials."""
        original = {
            "shodan_api_key": "SHODAN_KEY_ABC",
            "github_token": "ghp_1234567890abcdef",
        }
        bundle = export_bundle(original, mask=False)
        restored = import_bundle(bundle)
        assert restored == original


# ============================================================================
# API Router — List credentials
# ============================================================================


class TestListCredentials:
    """Tests for GET /v1/tenants/{tenant_id}/credentials/."""

    def test_list_returns_all_known_slots(self, client: TestClient) -> None:
        """The list endpoint returns every slot from KNOWN_SLOTS."""
        resp = client.get(f"/v1/tenants/{TENANT_ID_STR}/credentials/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_count"] == len(KNOWN_SLOTS)
        assert len(data["slots"]) == len(KNOWN_SLOTS)

    def test_all_slots_missing_initially(self, client: TestClient) -> None:
        """With an empty backend, all slots report 'missing' status."""
        resp = client.get(f"/v1/tenants/{TENANT_ID_STR}/credentials/")
        data = resp.json()
        assert data["configured_count"] == 0
        for slot in data["slots"]:
            assert slot["status"] == "missing"
            assert slot["masked_value"] is None

    async def test_configured_slot_shows_masked_value(
        self, client: TestClient, backend: InMemoryBackend
    ) -> None:
        """A stored credential shows as 'configured' with a masked value."""
        shodan_slot = _SLOTS_BY_ID["shodan_api_key"]
        await backend.set(
            tenant_id=TENANT_ID, key=shodan_slot.backend_key, value="REAL_KEY_XYZ_1234"
        )
        resp = client.get(f"/v1/tenants/{TENANT_ID_STR}/credentials/")
        data = resp.json()
        assert data["configured_count"] == 1

        shodan_entry = next(s for s in data["slots"] if s["credential_id"] == "shodan_api_key")
        assert shodan_entry["status"] == "configured"
        assert shodan_entry["masked_value"] == "****1234"

    def test_response_includes_tenant_id(self, client: TestClient) -> None:
        """Response includes the requested tenant_id."""
        resp = client.get(f"/v1/tenants/{TENANT_ID_STR}/credentials/")
        data = resp.json()
        assert data["tenant_id"] == TENANT_ID_STR


# ============================================================================
# API Router — Import SpiderFoot
# ============================================================================


class TestImportSpiderFoot:
    """Tests for POST /v1/tenants/{tenant_id}/credentials/import/spiderfoot."""

    def test_import_mapped_module(self, client: TestClient) -> None:
        """A known SpiderFoot module (sfp_shodan) imports to the correct slot."""
        resp = client.post(
            f"/v1/tenants/{TENANT_ID_STR}/credentials/import/spiderfoot",
            json={"credentials": {"sfp_shodan.api_key": "SHODAN_TEST_KEY"}},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["imported_count"] == 1
        assert "shodan_api_key" in data["slot_names"]

    def test_import_empty_value_skipped(self, client: TestClient) -> None:
        """Empty credential values are skipped with an error message."""
        resp = client.post(
            f"/v1/tenants/{TENANT_ID_STR}/credentials/import/spiderfoot",
            json={"credentials": {"sfp_shodan.api_key": ""}},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["imported_count"] == 0
        assert data["skipped_count"] == 1
        assert len(data["errors"]) == 1

    def test_import_multiple_modules(self, client: TestClient) -> None:
        """Multiple SpiderFoot modules import correctly."""
        resp = client.post(
            f"/v1/tenants/{TENANT_ID_STR}/credentials/import/spiderfoot",
            json={
                "credentials": {
                    "sfp_shodan.api_key": "SHODAN_KEY",
                    "sfp_securitytrails.api_key": "ST_KEY",
                    "sfp_greynoise.api_key": "GN_KEY",
                }
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["imported_count"] == 3


# ============================================================================
# API Router — Import Bundle
# ============================================================================


class TestImportBundle:
    """Tests for POST /v1/tenants/{tenant_id}/credentials/import/bundle."""

    def test_import_known_slot(self, client: TestClient) -> None:
        """A recognized credential slot ID is imported successfully."""
        resp = client.post(
            f"/v1/tenants/{TENANT_ID_STR}/credentials/import/bundle",
            json={"credentials": {"shodan_api_key": "MY_SHODAN_KEY"}},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["imported_count"] == 1
        assert "shodan_api_key" in data["slot_names"]

    def test_import_unknown_slot_skipped(self, client: TestClient) -> None:
        """An unknown credential slot ID is skipped with an error."""
        resp = client.post(
            f"/v1/tenants/{TENANT_ID_STR}/credentials/import/bundle",
            json={"credentials": {"nonexistent_key": "some-value"}},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["imported_count"] == 0
        assert data["skipped_count"] == 1
        assert any("Unknown credential slot" in e for e in data["errors"])

    def test_import_masked_value_rejected(self, client: TestClient) -> None:
        """Masked values (****...) are rejected to prevent overwriting real creds."""
        resp = client.post(
            f"/v1/tenants/{TENANT_ID_STR}/credentials/import/bundle",
            json={"credentials": {"shodan_api_key": "****1234"}},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["imported_count"] == 0
        assert data["skipped_count"] == 1
        assert any("masked" in e.lower() for e in data["errors"])

    async def test_import_stores_in_backend(
        self, client: TestClient, backend: InMemoryBackend
    ) -> None:
        """Imported credentials are actually stored in the backend."""
        client.post(
            f"/v1/tenants/{TENANT_ID_STR}/credentials/import/bundle",
            json={"credentials": {"github_token": "ghp_test123456"}},
        )
        slot_def = _SLOTS_BY_ID["github_token"]
        value = await backend.get(tenant_id=TENANT_ID, key=slot_def.backend_key)
        assert value == "ghp_test123456"

    def test_import_with_invalid_format_returns_errors(self, client: TestClient) -> None:
        """Import with a mix of valid and invalid keys reports partial success."""
        resp = client.post(
            f"/v1/tenants/{TENANT_ID_STR}/credentials/import/bundle",
            json={
                "credentials": {
                    "shodan_api_key": "VALID_KEY",
                    "totally_bogus": "some-val",
                    "github_token": "",
                }
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["imported_count"] == 1
        assert data["skipped_count"] == 2
        assert len(data["errors"]) == 2


# ============================================================================
# API Router — Export Bundle
# ============================================================================


class TestExportBundle:
    """Tests for GET /v1/tenants/{tenant_id}/credentials/export/bundle."""

    def test_export_empty_returns_no_credentials(self, client: TestClient) -> None:
        """With no stored credentials, export returns an empty dict."""
        resp = client.get(f"/v1/tenants/{TENANT_ID_STR}/credentials/export/bundle")
        assert resp.status_code == 200
        data = resp.json()
        assert data["credentials"] == {}
        assert data["format_version"] == "1.0"

    async def test_export_masks_values(
        self, client: TestClient, backend: InMemoryBackend
    ) -> None:
        """Exported credential values are masked (last 4 chars visible)."""
        slot_def = _SLOTS_BY_ID["shodan_api_key"]
        await backend.set(
            tenant_id=TENANT_ID, key=slot_def.backend_key, value="FULL_SECRET_VALUE_ABCD"
        )
        resp = client.get(f"/v1/tenants/{TENANT_ID_STR}/credentials/export/bundle")
        data = resp.json()
        assert "shodan_api_key" in data["credentials"]
        assert data["credentials"]["shodan_api_key"] == "****ABCD"
        # Full value must NOT appear in the response
        assert "FULL_SECRET_VALUE_ABCD" not in resp.text


# ============================================================================
# API Router — Test Credential
# ============================================================================


class TestTestCredential:
    """Tests for POST /v1/tenants/{tenant_id}/credentials/{credential_id}/test."""

    def test_unknown_credential_returns_404(self, client: TestClient) -> None:
        """Testing an unknown credential ID returns 404."""
        resp = client.post(
            f"/v1/tenants/{TENANT_ID_STR}/credentials/nonexistent_cred/test"
        )
        assert resp.status_code == 404

    def test_missing_credential_returns_not_configured(self, client: TestClient) -> None:
        """Testing a known but unconfigured credential returns not_configured."""
        resp = client.post(
            f"/v1/tenants/{TENANT_ID_STR}/credentials/shodan_api_key/test"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "not_configured"

    async def test_configured_credential_returns_ok(
        self, client: TestClient, backend: InMemoryBackend
    ) -> None:
        """Testing a configured credential returns ok."""
        slot_def = _SLOTS_BY_ID["shodan_api_key"]
        await backend.set(
            tenant_id=TENANT_ID, key=slot_def.backend_key, value="VALID_KEY_1234"
        )
        resp = client.post(
            f"/v1/tenants/{TENANT_ID_STR}/credentials/shodan_api_key/test"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["credential_id"] == "shodan_api_key"


# ============================================================================
# Round-trip integration test
# ============================================================================


class TestRoundTrip:
    """End-to-end round-trip: import -> list -> export -> verify."""

    async def test_import_export_round_trip(
        self, client: TestClient, backend: InMemoryBackend
    ) -> None:
        """Import credentials, export them, verify masked values match."""
        # 1. Import two credentials via bundle
        import_resp = client.post(
            f"/v1/tenants/{TENANT_ID_STR}/credentials/import/bundle",
            json={
                "credentials": {
                    "shodan_api_key": "SHODAN_ROUND_TRIP_KEY",
                    "github_token": "ghp_roundtriptest1234",
                }
            },
        )
        assert import_resp.status_code == 200
        import_data = import_resp.json()
        assert import_data["imported_count"] == 2

        # 2. List — both should be configured
        list_resp = client.get(f"/v1/tenants/{TENANT_ID_STR}/credentials/")
        list_data = list_resp.json()
        assert list_data["configured_count"] == 2
        configured_ids = {
            s["credential_id"] for s in list_data["slots"] if s["status"] == "configured"
        }
        assert "shodan_api_key" in configured_ids
        assert "github_token" in configured_ids

        # 3. Export — values should be masked
        export_resp = client.get(f"/v1/tenants/{TENANT_ID_STR}/credentials/export/bundle")
        export_data = export_resp.json()
        assert export_data["credentials"]["shodan_api_key"] == "****_KEY"
        assert export_data["credentials"]["github_token"] == "****1234"  # noqa: S105

        # 4. Verify the actual values in the backend are intact
        shodan_slot = _SLOTS_BY_ID["shodan_api_key"]
        github_slot = _SLOTS_BY_ID["github_token"]
        assert (
            await backend.get(tenant_id=TENANT_ID, key=shodan_slot.backend_key)
            == "SHODAN_ROUND_TRIP_KEY"
        )
        assert (
            await backend.get(tenant_id=TENANT_ID, key=github_slot.backend_key)
            == "ghp_roundtriptest1234"
        )
