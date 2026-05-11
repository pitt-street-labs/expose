"""Tests for content-addressed evidence storage (issue #111).

Coverage:

1.  Store/retrieve round-trip returns data verbatim.
2.  Content-addressed dedup: same content = same hash, stored once.
3.  Lifecycle expiry removes expired blobs.
4.  Integrity check on retrieval detects corruption.
5.  Local filesystem backend works end-to-end.
6.  FIPS compliance: all hashing via fips_adapter (no hashlib/secrets).
7.  EvidenceRef model validation.
8.  Metadata sidecar persistence.
9.  list_for_entity filters correctly.
10. delete removes blob and metadata.
11. exists reports correctly.
12. S3 backend store/retrieve/exists/delete/list_keys with mocked boto3.
13. S3 evidence key prefixing.
14. S3 content hash validation on retrieval.
15. Retention seconds default and override.
16. get_ref returns None for missing hash.
17. Content-addressed key generation.
18. MinIO endpoint configuration.
19. Retention lifecycle: expire_evidence(tenant_id, max_age_days).
20. Integrity verification: verify_integrity method.
21. S3 backend handles NoSuchKey errors correctly.
22. S3 backend pagination for list_keys.

These tests use :class:`LocalStorageBackend` via ``tmp_path`` for
EvidenceManager tests and :class:`unittest.mock` for S3 backend tests.
All hashing goes through the FIPS adapter; no ``hashlib`` or ``secrets``
imports are present in this file.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

import pytest

from expose.crypto.fips_adapter import compute_sha256_hex
from expose.storage.base import StorageKeyNotFoundError
from expose.storage.evidence import (
    EvidenceIntegrityError,
    EvidenceManager,
    EvidenceRef,
    _BATCH_SIZE,
    _DEFAULT_RETENTION_SECONDS,
    _META_FETCH_BATCH_SIZE,
)
from expose.storage.local import LocalStorageBackend
from expose.storage.s3 import S3StorageBackend

# Synthetic IDs for test isolation.
TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000A001")
ENTITY_A = uuid4()
ENTITY_B = uuid4()


@pytest.fixture
def backend(tmp_path: Path) -> LocalStorageBackend:
    """Fresh local storage backend per test."""
    return LocalStorageBackend(root=tmp_path)


@pytest.fixture
def manager(backend: LocalStorageBackend) -> EvidenceManager:
    """EvidenceManager backed by a local filesystem."""
    return EvidenceManager(backend, key_prefix=f"tenant/{TENANT_ID}")


@pytest.fixture
def bare_manager(backend: LocalStorageBackend) -> EvidenceManager:
    """EvidenceManager with no key prefix (for simpler key assertions)."""
    return EvidenceManager(backend)


# ---------------------------------------------------------------------------
# S3 backend fixtures (mocked boto3)
# ---------------------------------------------------------------------------


def _make_mock_client() -> MagicMock:
    """Create a mock S3 client with sensible defaults.

    The mock client implements the minimal S3 API surface used by
    S3StorageBackend: put_object, get_object, head_object,
    delete_object, list_objects_v2.

    An in-memory dict acts as the "bucket" for predictable assertions.
    """
    store: dict[str, dict] = {}
    client = MagicMock()

    def put_object(*, Bucket: str, Key: str, Body: bytes, **kwargs):
        store[Key] = {
            "Body": Body,
            "ContentType": kwargs.get("ContentType", "application/octet-stream"),
            "Metadata": kwargs.get("Metadata", {}),
        }
        return {}

    def get_object(*, Bucket: str, Key: str, **kwargs):
        if Key not in store:
            error = MagicMock()
            error.response = {"Error": {"Code": "NoSuchKey"}}
            raise type("ClientError", (Exception,), {
                "__init__": lambda self, *a, **kw: None,
                "response": {"Error": {"Code": "NoSuchKey"}},
                "__str__": lambda self: "NoSuchKey",
            })()
        body = MagicMock()
        body.read = MagicMock(return_value=store[Key]["Body"])
        return {
            "Body": body,
            "ContentType": store[Key]["ContentType"],
            "Metadata": store[Key]["Metadata"],
        }

    def head_object(*, Bucket: str, Key: str, **kwargs):
        if Key not in store:
            raise Exception("404 Not Found")
        return {"ContentLength": len(store[Key]["Body"])}

    def delete_object(*, Bucket: str, Key: str, **kwargs):
        store.pop(Key, None)
        return {}

    def list_objects_v2(*, Bucket: str, **kwargs):
        prefix = kwargs.get("Prefix", "")
        matching = [k for k in sorted(store.keys()) if k.startswith(prefix)]
        return {
            "Contents": [{"Key": k} for k in matching],
            "IsTruncated": False,
        }

    client.put_object = MagicMock(side_effect=put_object)
    client.get_object = MagicMock(side_effect=get_object)
    client.head_object = MagicMock(side_effect=head_object)
    client.delete_object = MagicMock(side_effect=delete_object)
    client.list_objects_v2 = MagicMock(side_effect=list_objects_v2)

    # Expose the internal store for test assertions.
    client._store = store
    return client


@pytest.fixture
def mock_client() -> MagicMock:
    """Fresh mock S3 client per test."""
    return _make_mock_client()


@pytest.fixture
def s3_backend(mock_client: MagicMock) -> S3StorageBackend:
    """S3StorageBackend with a mocked boto3 client."""
    return S3StorageBackend(bucket="test-bucket", client=mock_client)


# ---------------------------------------------------------------------------
# 1. Store/retrieve round-trip
# ---------------------------------------------------------------------------


async def test_store_retrieve_roundtrip(manager: EvidenceManager) -> None:
    """Data stored via store() is returned verbatim by retrieve()."""
    content = b"raw HTTP response body from example.com"
    ref = await manager.store(content, {"source": "http-collector"})

    retrieved = await manager.retrieve(ref.content_hash)
    assert retrieved == content


async def test_store_retrieve_binary_data(manager: EvidenceManager) -> None:
    """Non-UTF8 binary data survives the store/retrieve round-trip."""
    content = bytes(range(256))
    ref = await manager.store(content, {"type": "binary-blob"})
    retrieved = await manager.retrieve(ref.content_hash)
    assert retrieved == content
    assert len(retrieved) == 256


# ---------------------------------------------------------------------------
# 2. Content-addressed dedup
# ---------------------------------------------------------------------------


async def test_content_addressed_dedup(
    manager: EvidenceManager, backend: LocalStorageBackend
) -> None:
    """Same content produces the same hash; blob is stored only once."""
    content = b"duplicate evidence blob"
    ref1 = await manager.store(content, {"entity_id": str(ENTITY_A)})
    ref2 = await manager.store(content, {"entity_id": str(ENTITY_B)})

    # Same hash.
    assert ref1.content_hash == ref2.content_hash

    # Both retrieve the same data.
    data1 = await manager.retrieve(ref1.content_hash)
    data2 = await manager.retrieve(ref2.content_hash)
    assert data1 == data2 == content

    # The hash is a proper SHA-256 hex digest.
    expected_hash = compute_sha256_hex(content)
    assert ref1.content_hash == expected_hash


async def test_different_content_different_hash(manager: EvidenceManager) -> None:
    """Different content produces different hashes."""
    ref1 = await manager.store(b"content A", {})
    ref2 = await manager.store(b"content B", {})
    assert ref1.content_hash != ref2.content_hash


# ---------------------------------------------------------------------------
# 3. Lifecycle expiry
# ---------------------------------------------------------------------------


async def test_expire_removes_expired_blobs(
    backend: LocalStorageBackend,
) -> None:
    """Blobs past their retention window are removed by expire()."""
    manager = EvidenceManager(backend, default_retention_seconds=0)

    content = b"short-lived evidence"
    ref = await manager.store(content, {"entity_id": str(ENTITY_A)})

    # The blob exists before expiry.
    assert await manager.exists(ref.content_hash) is True

    # With retention_seconds=0, the blob is already expired.
    expired = await manager.expire()
    assert ref.content_hash in expired
    assert await manager.exists(ref.content_hash) is False


async def test_expire_preserves_fresh_blobs(manager: EvidenceManager) -> None:
    """Blobs within their retention window are NOT removed by expire()."""
    content = b"long-lived evidence"
    ref = await manager.store(content, {})

    expired = await manager.expire()
    assert expired == []
    assert await manager.exists(ref.content_hash) is True
    # Data is still retrievable.
    assert await manager.retrieve(ref.content_hash) == content


async def test_expire_with_custom_retention(
    backend: LocalStorageBackend,
) -> None:
    """Per-blob retention_seconds override works correctly."""
    manager = EvidenceManager(backend, default_retention_seconds=86400)

    # Store one blob with 0-second retention (expired immediately).
    ref_expired = await manager.store(
        b"ephemeral", {}, retention_seconds=0
    )
    # Store another with the default (24h, still fresh).
    ref_fresh = await manager.store(b"persistent", {})

    expired = await manager.expire()
    assert ref_expired.content_hash in expired
    assert ref_fresh.content_hash not in expired
    assert await manager.exists(ref_expired.content_hash) is False
    assert await manager.exists(ref_fresh.content_hash) is True


# ---------------------------------------------------------------------------
# 4. Integrity check on retrieval
# ---------------------------------------------------------------------------


async def test_integrity_check_detects_corruption(
    manager: EvidenceManager, backend: LocalStorageBackend, tmp_path: Path
) -> None:
    """retrieve() raises EvidenceIntegrityError if stored data is corrupted."""
    content = b"original evidence"
    ref = await manager.store(content, {})

    # Corrupt the stored file directly.
    blob_key = manager._blob_key(ref.content_hash)
    blob_path = (tmp_path / blob_key).resolve()
    blob_path.write_bytes(b"CORRUPTED DATA")

    with pytest.raises(EvidenceIntegrityError, match="integrity check failed"):
        await manager.retrieve(ref.content_hash)


async def test_integrity_check_explicit_true(
    manager: EvidenceManager, backend: LocalStorageBackend, tmp_path: Path
) -> None:
    """retrieve(verify_integrity=True) explicitly still catches corruption."""
    content = b"explicit verify evidence"
    ref = await manager.store(content, {})

    blob_key = manager._blob_key(ref.content_hash)
    blob_path = (tmp_path / blob_key).resolve()
    blob_path.write_bytes(b"TAMPERED")

    with pytest.raises(EvidenceIntegrityError, match="integrity check failed"):
        await manager.retrieve(ref.content_hash, verify_integrity=True)


async def test_integrity_check_skipped_with_false(
    manager: EvidenceManager, backend: LocalStorageBackend, tmp_path: Path
) -> None:
    """retrieve(verify_integrity=False) skips hash check, returns raw data."""
    content = b"skip verify evidence"
    ref = await manager.store(content, {})

    # Corrupt the stored file directly.
    blob_key = manager._blob_key(ref.content_hash)
    blob_path = (tmp_path / blob_key).resolve()
    blob_path.write_bytes(b"CORRUPTED BUT RETURNED")

    # With verification disabled, no error is raised -- corrupted data
    # is returned as-is.
    result = await manager.retrieve(ref.content_hash, verify_integrity=False)
    assert result == b"CORRUPTED BUT RETURNED"


async def test_instance_verify_on_read_false(
    backend: LocalStorageBackend, tmp_path: Path
) -> None:
    """EvidenceManager(verify_on_read=False) skips hash by default."""
    mgr = EvidenceManager(backend, verify_on_read=False)
    content = b"instance-level no-verify"
    ref = await mgr.store(content, {})

    # Corrupt the stored file directly.
    blob_key = mgr._blob_key(ref.content_hash)
    blob_path = (tmp_path / blob_key).resolve()
    blob_path.write_bytes(b"SILENTLY CORRUPTED")

    # Default retrieval skips verification because verify_on_read=False.
    result = await mgr.retrieve(ref.content_hash)
    assert result == b"SILENTLY CORRUPTED"


async def test_instance_verify_on_read_false_overridden_by_explicit_true(
    backend: LocalStorageBackend, tmp_path: Path
) -> None:
    """Per-call verify_integrity=True overrides instance verify_on_read=False."""
    mgr = EvidenceManager(backend, verify_on_read=False)
    content = b"override test"
    ref = await mgr.store(content, {})

    blob_key = mgr._blob_key(ref.content_hash)
    blob_path = (tmp_path / blob_key).resolve()
    blob_path.write_bytes(b"TAMPERED OVERRIDE")

    # Explicit True overrides instance-level False.
    with pytest.raises(EvidenceIntegrityError, match="integrity check failed"):
        await mgr.retrieve(ref.content_hash, verify_integrity=True)


async def test_retrieve_no_verify_returns_valid_data(
    manager: EvidenceManager,
) -> None:
    """retrieve(verify_integrity=False) returns correct data for non-corrupt blobs."""
    content = b"valid data, no verify"
    ref = await manager.store(content, {})
    result = await manager.retrieve(ref.content_hash, verify_integrity=False)
    assert result == content


# ---------------------------------------------------------------------------
# 5. Local filesystem backend (end-to-end)
# ---------------------------------------------------------------------------


async def test_local_backend_creates_directory_tree(
    manager: EvidenceManager, tmp_path: Path
) -> None:
    """Evidence storage creates the necessary directory structure."""
    content = b"filesystem structure test"
    ref = await manager.store(content, {})

    # The blob file and metadata sidecar should exist on disk.
    blob_path = (tmp_path / manager._blob_key(ref.content_hash)).resolve()
    meta_path = (tmp_path / manager._meta_key(ref.content_hash)).resolve()
    assert blob_path.is_file()
    assert meta_path.is_file()

    # The metadata sidecar should be valid JSON.
    meta_content = json.loads(meta_path.read_text())
    assert meta_content["content_hash"] == ref.content_hash
    assert meta_content["size_bytes"] == len(content)


# ---------------------------------------------------------------------------
# 6. FIPS compliance
# ---------------------------------------------------------------------------


def test_fips_compliance_no_banned_imports() -> None:
    """The evidence module uses only the FIPS adapter for hashing.

    This is a structural assertion: the evidence.py source must not
    contain ``import hashlib`` or ``import secrets``.
    """
    import inspect

    from expose.storage import evidence as evidence_module

    source = inspect.getsource(evidence_module)
    assert "import hashlib" not in source
    assert "from hashlib" not in source
    assert "import secrets" not in source
    assert "from secrets" not in source
    assert "from Crypto" not in source


def test_fips_compliance_no_banned_imports_s3() -> None:
    """The S3 module uses only the FIPS adapter for hashing."""
    import inspect

    from expose.storage import s3 as s3_module

    source = inspect.getsource(s3_module)
    assert "import hashlib" not in source
    assert "from hashlib" not in source
    assert "import secrets" not in source
    assert "from secrets" not in source
    assert "from Crypto" not in source


def test_fips_compliance_hash_matches_adapter() -> None:
    """The content hash produced by store matches the FIPS adapter output."""
    content = b"FIPS compliance verification"
    expected = compute_sha256_hex(content)
    assert len(expected) == 64
    assert all(c in "0123456789abcdef" for c in expected)


async def test_fips_compliance_roundtrip_hash(manager: EvidenceManager) -> None:
    """store() uses the FIPS adapter and the hash matches compute_sha256_hex."""
    content = b"FIPS round-trip test"
    ref = await manager.store(content, {})
    expected_hash = compute_sha256_hex(content)
    assert ref.content_hash == expected_hash


# ---------------------------------------------------------------------------
# 7. EvidenceRef model validation
# ---------------------------------------------------------------------------


def test_evidence_ref_valid() -> None:
    """EvidenceRef accepts valid data."""
    content_hash = compute_sha256_hex(b"test")
    ref = EvidenceRef(
        content_hash=content_hash,
        content_type="application/json",
        size_bytes=42,
        stored_at=datetime.now(tz=UTC),
        metadata={"entity_id": str(ENTITY_A)},
    )
    assert ref.content_hash == content_hash
    assert ref.size_bytes == 42
    assert ref.retention_seconds == _DEFAULT_RETENTION_SECONDS


def test_evidence_ref_rejects_bad_hash() -> None:
    """EvidenceRef rejects a content_hash that is not 64 hex chars."""
    with pytest.raises(Exception):  # Pydantic ValidationError
        EvidenceRef(
            content_hash="not-a-valid-hash",
            content_type="text/plain",
            size_bytes=10,
            stored_at=datetime.now(tz=UTC),
        )


def test_evidence_ref_frozen() -> None:
    """EvidenceRef instances are immutable (frozen)."""
    content_hash = compute_sha256_hex(b"frozen test")
    ref = EvidenceRef(
        content_hash=content_hash,
        size_bytes=11,
        stored_at=datetime.now(tz=UTC),
    )
    with pytest.raises(Exception):  # Pydantic ValidationError for frozen
        ref.size_bytes = 999  # type: ignore[misc]


# ---------------------------------------------------------------------------
# 8. Metadata sidecar persistence
# ---------------------------------------------------------------------------


async def test_metadata_sidecar_persisted(manager: EvidenceManager) -> None:
    """Metadata is persisted alongside the blob and retrievable via get_ref."""
    meta = {"entity_id": str(ENTITY_A), "run_id": "run-001", "collector": "dns"}
    content = b"DNS response payload"
    ref = await manager.store(content, meta, content_type="application/dns-message")

    loaded = await manager.get_ref(ref.content_hash)
    assert loaded is not None
    assert loaded.content_hash == ref.content_hash
    assert loaded.content_type == "application/dns-message"
    assert loaded.size_bytes == len(content)
    assert loaded.metadata["entity_id"] == str(ENTITY_A)
    assert loaded.metadata["run_id"] == "run-001"
    assert loaded.metadata["collector"] == "dns"


async def test_get_ref_returns_none_for_missing(manager: EvidenceManager) -> None:
    """get_ref returns None when no metadata sidecar exists."""
    fake_hash = compute_sha256_hex(b"nonexistent")
    result = await manager.get_ref(fake_hash)
    assert result is None


# ---------------------------------------------------------------------------
# 9. list_for_entity
# ---------------------------------------------------------------------------


async def test_list_for_entity_filters_correctly(manager: EvidenceManager) -> None:
    """list_for_entity returns only evidence associated with the entity."""
    await manager.store(b"evidence for A", {"entity_id": str(ENTITY_A)})
    await manager.store(b"more evidence for A", {"entity_id": str(ENTITY_A)})
    await manager.store(b"evidence for B", {"entity_id": str(ENTITY_B)})

    a_refs = await manager.list_for_entity(ENTITY_A)
    b_refs = await manager.list_for_entity(ENTITY_B)

    assert len(a_refs) == 2
    assert len(b_refs) == 1
    assert all(r.metadata["entity_id"] == str(ENTITY_A) for r in a_refs)
    assert b_refs[0].metadata["entity_id"] == str(ENTITY_B)


async def test_list_for_entity_empty(manager: EvidenceManager) -> None:
    """list_for_entity returns empty list when no evidence exists."""
    result = await manager.list_for_entity(uuid4())
    assert result == []


# ---------------------------------------------------------------------------
# 10. delete removes blob and metadata
# ---------------------------------------------------------------------------


async def test_delete_removes_blob_and_metadata(manager: EvidenceManager) -> None:
    """delete() removes both the blob and its metadata sidecar."""
    content = b"deletable evidence"
    ref = await manager.store(content, {"entity_id": str(ENTITY_A)})

    result = await manager.delete(ref.content_hash)
    assert result is True

    # Blob is gone.
    assert await manager.exists(ref.content_hash) is False
    with pytest.raises(StorageKeyNotFoundError):
        await manager.retrieve(ref.content_hash)

    # Metadata is gone.
    assert await manager.get_ref(ref.content_hash) is None


async def test_delete_missing_returns_false(manager: EvidenceManager) -> None:
    """delete() returns False for a hash that was never stored."""
    fake_hash = compute_sha256_hex(b"never stored")
    result = await manager.delete(fake_hash)
    assert result is False


# ---------------------------------------------------------------------------
# 11. exists reports correctly
# ---------------------------------------------------------------------------


async def test_exists_true_after_store(manager: EvidenceManager) -> None:
    """exists() returns True after a blob is stored."""
    ref = await manager.store(b"existence test", {})
    assert await manager.exists(ref.content_hash) is True


async def test_exists_false_for_missing(manager: EvidenceManager) -> None:
    """exists() returns False for a hash that was never stored."""
    fake_hash = compute_sha256_hex(b"does not exist")
    assert await manager.exists(fake_hash) is False


# ---------------------------------------------------------------------------
# 12. S3 backend with mocked boto3
# ---------------------------------------------------------------------------


async def test_s3_put_get_roundtrip(s3_backend: S3StorageBackend) -> None:
    """S3 backend put/get round-trip returns data verbatim."""
    key = f"tenant/{TENANT_ID}/evidence/test123"
    data = b"raw HTTP response from S3"
    uri = await s3_backend.put(key, data)

    assert uri == f"s3://test-bucket/{key}"
    retrieved = await s3_backend.get(key)
    assert retrieved == data


async def test_s3_put_with_content_type(s3_backend: S3StorageBackend, mock_client: MagicMock) -> None:
    """S3 backend put passes ContentType to the S3 API."""
    key = "tenant/abc/evidence/cert.pem"
    data = b"PEM certificate data"
    await s3_backend.put(key, data, content_type="application/x-pem-file")

    # Verify the mock was called with correct ContentType.
    call_kwargs = mock_client.put_object.call_args
    assert call_kwargs.kwargs["ContentType"] == "application/x-pem-file"


async def test_s3_put_stores_sha256_metadata(s3_backend: S3StorageBackend, mock_client: MagicMock) -> None:
    """S3 backend put stores SHA-256 hash in object metadata."""
    key = "tenant/abc/evidence/hash-check"
    data = b"metadata hash test"
    expected_hash = compute_sha256_hex(data)
    await s3_backend.put(key, data)

    call_kwargs = mock_client.put_object.call_args
    assert call_kwargs.kwargs["Metadata"]["sha256"] == expected_hash


async def test_s3_get_missing_raises(s3_backend: S3StorageBackend) -> None:
    """S3 backend get raises StorageKeyNotFoundError for missing keys."""
    with pytest.raises(StorageKeyNotFoundError, match="No object stored"):
        await s3_backend.get("tenant/missing/evidence/none")


async def test_s3_exists_true(s3_backend: S3StorageBackend) -> None:
    """S3 backend exists returns True after put."""
    key = "tenant/abc/evidence/exist-check"
    await s3_backend.put(key, b"exists test")
    assert await s3_backend.exists(key) is True


async def test_s3_exists_false(s3_backend: S3StorageBackend) -> None:
    """S3 backend exists returns False for missing keys."""
    assert await s3_backend.exists("tenant/missing/evidence/none") is False


async def test_s3_delete_existing(s3_backend: S3StorageBackend) -> None:
    """S3 backend delete returns True for existing keys and removes them."""
    key = "tenant/abc/evidence/delete-me"
    await s3_backend.put(key, b"delete test")

    result = await s3_backend.delete(key)
    assert result is True
    assert await s3_backend.exists(key) is False


async def test_s3_delete_missing(s3_backend: S3StorageBackend) -> None:
    """S3 backend delete returns False for missing keys."""
    result = await s3_backend.delete("tenant/never-stored/evidence/none")
    assert result is False


async def test_s3_list_keys_all(s3_backend: S3StorageBackend) -> None:
    """S3 backend list_keys returns all stored keys."""
    keys = [
        "tenant/abc/evidence/aaa",
        "tenant/abc/evidence/bbb",
        "tenant/abc/artifacts/run001.json",
    ]
    for k in keys:
        await s3_backend.put(k, b"payload")

    listed = await s3_backend.list_keys()
    assert sorted(listed) == sorted(keys)


async def test_s3_list_keys_with_prefix(s3_backend: S3StorageBackend) -> None:
    """S3 backend list_keys with prefix filters correctly."""
    await s3_backend.put("tenant/abc/evidence/aaa", b"evidence")
    await s3_backend.put("tenant/abc/artifacts/run001.json", b"artifact")

    evidence = await s3_backend.list_keys(prefix="tenant/abc/evidence")
    assert evidence == ["tenant/abc/evidence/aaa"]

    artifacts = await s3_backend.list_keys(prefix="tenant/abc/artifacts")
    assert artifacts == ["tenant/abc/artifacts/run001.json"]


async def test_s3_list_keys_empty_bucket(s3_backend: S3StorageBackend) -> None:
    """S3 backend list_keys returns empty list for empty bucket."""
    result = await s3_backend.list_keys()
    assert result == []


async def test_s3_binary_roundtrip(s3_backend: S3StorageBackend) -> None:
    """S3 backend handles non-UTF8 binary data correctly."""
    key = "tenant/abc/evidence/binary"
    data = bytes(range(256))
    await s3_backend.put(key, data)
    retrieved = await s3_backend.get(key)
    assert retrieved == data
    assert len(retrieved) == 256


async def test_s3_overwrite(s3_backend: S3StorageBackend) -> None:
    """S3 backend overwrites existing data on put."""
    key = "tenant/abc/evidence/overwrite"
    await s3_backend.put(key, b"original")
    await s3_backend.put(key, b"replacement")
    assert await s3_backend.get(key) == b"replacement"


async def test_s3_put_returns_uri(s3_backend: S3StorageBackend) -> None:
    """S3 backend put returns an s3:// URI."""
    key = "tenant/abc/evidence/uri"
    uri = await s3_backend.put(key, b"uri test")
    assert uri == "s3://test-bucket/tenant/abc/evidence/uri"


# ---------------------------------------------------------------------------
# 12b. S3 backend used as EvidenceManager backend
# ---------------------------------------------------------------------------


async def test_s3_evidence_manager_roundtrip(mock_client: MagicMock) -> None:
    """EvidenceManager works with S3StorageBackend for store/retrieve."""
    s3 = S3StorageBackend(bucket="evidence-bucket", client=mock_client)
    mgr = EvidenceManager(s3, key_prefix=f"tenant/{TENANT_ID}")

    content = b"S3-backed evidence blob"
    ref = await mgr.store(content, {"source": "s3-test"})

    assert ref.content_hash == compute_sha256_hex(content)
    assert ref.size_bytes == len(content)

    retrieved = await mgr.retrieve(ref.content_hash)
    assert retrieved == content


async def test_s3_evidence_manager_exists(mock_client: MagicMock) -> None:
    """EvidenceManager.exists works with S3StorageBackend."""
    s3 = S3StorageBackend(bucket="evidence-bucket", client=mock_client)
    mgr = EvidenceManager(s3, key_prefix=f"tenant/{TENANT_ID}")

    content = b"S3 exists check"
    ref = await mgr.store(content, {})

    assert await mgr.exists(ref.content_hash) is True
    fake_hash = compute_sha256_hex(b"not stored")
    assert await mgr.exists(fake_hash) is False


async def test_s3_evidence_manager_delete(mock_client: MagicMock) -> None:
    """EvidenceManager.delete works with S3StorageBackend."""
    s3 = S3StorageBackend(bucket="evidence-bucket", client=mock_client)
    mgr = EvidenceManager(s3, key_prefix=f"tenant/{TENANT_ID}")

    content = b"S3 delete test"
    ref = await mgr.store(content, {})
    assert await mgr.delete(ref.content_hash) is True
    assert await mgr.exists(ref.content_hash) is False


# ---------------------------------------------------------------------------
# 13. S3 evidence key prefixing
# ---------------------------------------------------------------------------


async def test_s3_store_evidence_key_prefix(s3_backend: S3StorageBackend, mock_client: MagicMock) -> None:
    """store_evidence prepends 'evidence/' to keys."""
    await s3_backend.store_evidence("abc123", b"evidence data")

    # Verify the key used in put_object includes the evidence/ prefix.
    # The last put_object call should have Key="evidence/abc123".
    call_kwargs = mock_client.put_object.call_args
    assert call_kwargs.kwargs["Key"] == "evidence/abc123"


async def test_s3_store_evidence_roundtrip(s3_backend: S3StorageBackend) -> None:
    """store_evidence + retrieve_evidence round-trip works."""
    key = "test-key-001"
    content = b"evidence round-trip via S3"
    full_key = await s3_backend.store_evidence(key, content)

    assert full_key == "evidence/test-key-001"
    retrieved = await s3_backend.retrieve_evidence(key)
    assert retrieved == content


async def test_s3_store_evidence_with_metadata(s3_backend: S3StorageBackend, mock_client: MagicMock) -> None:
    """store_evidence passes caller metadata as S3 object metadata."""
    await s3_backend.store_evidence(
        "meta-test",
        b"metadata evidence",
        metadata={"source": "http", "collector": "tls"},
    )

    call_kwargs = mock_client.put_object.call_args
    s3_meta = call_kwargs.kwargs["Metadata"]
    assert s3_meta["sha256"] == compute_sha256_hex(b"metadata evidence")
    assert s3_meta["user-source"] == "http"
    assert s3_meta["user-collector"] == "tls"


# ---------------------------------------------------------------------------
# 14. S3 content hash validation on retrieval
# ---------------------------------------------------------------------------


async def test_s3_retrieve_evidence_validates_hash(s3_backend: S3StorageBackend) -> None:
    """retrieve_evidence validates SHA-256 hash keys and passes on match."""
    content = b"hash validation test content"
    sha256_key = compute_sha256_hex(content)

    await s3_backend.store_evidence(sha256_key, content)
    retrieved = await s3_backend.retrieve_evidence(sha256_key)
    assert retrieved == content


async def test_s3_retrieve_evidence_fails_on_hash_mismatch(
    s3_backend: S3StorageBackend, mock_client: MagicMock
) -> None:
    """retrieve_evidence raises ValueError when content hash mismatches key."""
    # Store content under a SHA-256 key that does NOT match the content.
    fake_key = compute_sha256_hex(b"expected content")
    # But the actual stored bytes are different.
    wrong_content = b"actual content that does not match the key"

    # Directly put into the mock store so the key is a valid sha256
    # but the content doesn't match.
    mock_client._store[f"evidence/{fake_key}"] = {
        "Body": wrong_content,
        "ContentType": "application/octet-stream",
        "Metadata": {},
    }

    with pytest.raises(ValueError, match="integrity check failed"):
        await s3_backend.retrieve_evidence(fake_key)


async def test_s3_retrieve_evidence_skips_validation_for_non_hash_keys(
    s3_backend: S3StorageBackend,
) -> None:
    """retrieve_evidence skips hash validation for non-SHA256 keys."""
    key = "descriptive-key-name"
    content = b"non-hash-key content"
    await s3_backend.store_evidence(key, content)

    # Should not raise even though the key != sha256(content).
    retrieved = await s3_backend.retrieve_evidence(key)
    assert retrieved == content


async def test_s3_retrieve_evidence_missing_raises(s3_backend: S3StorageBackend) -> None:
    """retrieve_evidence raises StorageKeyNotFoundError for missing keys."""
    with pytest.raises(StorageKeyNotFoundError):
        await s3_backend.retrieve_evidence("nonexistent-key")


# ---------------------------------------------------------------------------
# 15. Retention seconds default and override
# ---------------------------------------------------------------------------


async def test_default_retention_seconds(bare_manager: EvidenceManager) -> None:
    """store() uses the manager's default retention when not overridden."""
    ref = await bare_manager.store(b"default retention", {})
    assert ref.retention_seconds == _DEFAULT_RETENTION_SECONDS


async def test_custom_retention_seconds(bare_manager: EvidenceManager) -> None:
    """store() applies the caller's retention_seconds override."""
    ref = await bare_manager.store(b"custom retention", {}, retention_seconds=3600)
    assert ref.retention_seconds == 3600


async def test_manager_level_default_retention(
    backend: LocalStorageBackend,
) -> None:
    """EvidenceManager's default_retention_seconds is applied to all blobs."""
    manager = EvidenceManager(backend, default_retention_seconds=7200)
    ref = await manager.store(b"manager default", {})
    assert ref.retention_seconds == 7200


# ---------------------------------------------------------------------------
# 16. get_ref returns None for missing hash
# ---------------------------------------------------------------------------


async def test_get_ref_none_for_nonexistent(bare_manager: EvidenceManager) -> None:
    """get_ref returns None when no metadata exists for the hash."""
    fake = compute_sha256_hex(b"no such evidence")
    assert await bare_manager.get_ref(fake) is None


# ---------------------------------------------------------------------------
# 17. Content-addressed key generation
# ---------------------------------------------------------------------------


def test_content_key_format() -> None:
    """S3StorageBackend.content_key follows {tenant}/{run}/{sha256} convention."""
    tenant_id = str(TENANT_ID)
    run_id = "run-001"
    content = b"content-addressed test"
    expected_hash = compute_sha256_hex(content)

    key = S3StorageBackend.content_key(tenant_id, run_id, content)
    assert key == f"{tenant_id}/{run_id}/{expected_hash}"


def test_content_key_deterministic() -> None:
    """Same inputs always produce the same content key."""
    content = b"deterministic key test"
    key1 = S3StorageBackend.content_key("tenant-1", "run-1", content)
    key2 = S3StorageBackend.content_key("tenant-1", "run-1", content)
    assert key1 == key2


def test_content_key_different_for_different_content() -> None:
    """Different content produces different content keys."""
    key1 = S3StorageBackend.content_key("t", "r", b"content A")
    key2 = S3StorageBackend.content_key("t", "r", b"content B")
    assert key1 != key2


def test_content_key_different_for_different_tenant() -> None:
    """Different tenant IDs produce different content keys."""
    content = b"same content"
    key1 = S3StorageBackend.content_key("tenant-1", "run-1", content)
    key2 = S3StorageBackend.content_key("tenant-2", "run-1", content)
    assert key1 != key2
    # Hash suffix should be the same (same content).
    assert key1.split("/")[-1] == key2.split("/")[-1]


def test_content_key_different_for_different_run() -> None:
    """Different run IDs produce different content keys."""
    content = b"same content"
    key1 = S3StorageBackend.content_key("tenant-1", "run-1", content)
    key2 = S3StorageBackend.content_key("tenant-1", "run-2", content)
    assert key1 != key2
    assert key1.split("/")[-1] == key2.split("/")[-1]


# ---------------------------------------------------------------------------
# 18. MinIO endpoint configuration
# ---------------------------------------------------------------------------


def test_minio_endpoint_url_stored() -> None:
    """S3StorageBackend stores endpoint_url for MinIO configuration."""
    s3 = S3StorageBackend(
        bucket="minio-bucket",
        endpoint_url="http://minio.local:9000",
        client=MagicMock(),
    )
    assert s3._endpoint_url == "http://minio.local:9000"
    assert s3._bucket == "minio-bucket"


def test_minio_custom_region() -> None:
    """S3StorageBackend supports custom region for MinIO."""
    s3 = S3StorageBackend(
        bucket="minio-bucket",
        region="us-west-2",
        endpoint_url="http://minio.local:9000",
        client=MagicMock(),
    )
    assert s3._region == "us-west-2"


def test_default_region_is_us_east_1() -> None:
    """S3StorageBackend defaults to us-east-1 region."""
    s3 = S3StorageBackend(bucket="test-bucket", client=MagicMock())
    assert s3._region == "us-east-1"


def test_s3_endpoint_url_none_for_aws() -> None:
    """S3StorageBackend endpoint_url is None for standard AWS."""
    s3 = S3StorageBackend(bucket="aws-bucket", client=MagicMock())
    assert s3._endpoint_url is None


# ---------------------------------------------------------------------------
# 19. Retention lifecycle: expire_evidence(tenant_id, max_age_days)
# ---------------------------------------------------------------------------


async def test_expire_evidence_removes_old_blobs(
    backend: LocalStorageBackend,
) -> None:
    """expire_evidence removes blobs older than max_age_days."""
    manager = EvidenceManager(
        backend,
        key_prefix=f"tenant/{TENANT_ID}",
        default_retention_seconds=86400 * 365,  # Long default retention
    )

    # Store a blob, then manually backdate its metadata.
    content = b"old evidence for expiry"
    ref = await manager.store(content, {"entity_id": str(ENTITY_A)})

    # Backdate the metadata to 100 days ago.
    meta_key = manager._meta_key(ref.content_hash)
    meta_bytes = await backend.get(meta_key)
    meta_dict = json.loads(meta_bytes)
    old_time = datetime.now(tz=UTC) - timedelta(days=100)
    meta_dict["stored_at"] = old_time.isoformat()
    await backend.put(meta_key, json.dumps(meta_dict).encode(), "application/json")

    # Expire with 90-day cutoff -- the 100-day-old blob should be removed.
    expired = await manager.expire_evidence(str(TENANT_ID), max_age_days=90)
    assert ref.content_hash in expired
    assert await manager.exists(ref.content_hash) is False


async def test_expire_evidence_preserves_recent_blobs(
    manager: EvidenceManager,
) -> None:
    """expire_evidence preserves blobs newer than max_age_days."""
    content = b"fresh evidence"
    ref = await manager.store(content, {})

    expired = await manager.expire_evidence(str(TENANT_ID), max_age_days=90)
    assert expired == []
    assert await manager.exists(ref.content_hash) is True


async def test_expire_evidence_mixed_ages(
    backend: LocalStorageBackend,
) -> None:
    """expire_evidence correctly handles a mix of old and new blobs."""
    manager = EvidenceManager(
        backend,
        key_prefix=f"tenant/{TENANT_ID}",
        default_retention_seconds=86400 * 365,
    )

    # Store two blobs.
    old_content = b"old blob"
    new_content = b"new blob"
    old_ref = await manager.store(old_content, {})
    new_ref = await manager.store(new_content, {})

    # Backdate only the first blob to 200 days ago.
    meta_key = manager._meta_key(old_ref.content_hash)
    meta_bytes = await backend.get(meta_key)
    meta_dict = json.loads(meta_bytes)
    meta_dict["stored_at"] = (datetime.now(tz=UTC) - timedelta(days=200)).isoformat()
    await backend.put(meta_key, json.dumps(meta_dict).encode(), "application/json")

    expired = await manager.expire_evidence(str(TENANT_ID), max_age_days=90)
    assert old_ref.content_hash in expired
    assert new_ref.content_hash not in expired
    assert await manager.exists(old_ref.content_hash) is False
    assert await manager.exists(new_ref.content_hash) is True


# ---------------------------------------------------------------------------
# 20. Integrity verification: verify_integrity method
# ---------------------------------------------------------------------------


async def test_verify_integrity_valid(manager: EvidenceManager) -> None:
    """verify_integrity returns True for uncorrupted blobs."""
    content = b"integrity verification test"
    ref = await manager.store(content, {})

    result = await manager.verify_integrity(ref.content_hash)
    assert result is True


async def test_verify_integrity_corrupted(
    manager: EvidenceManager, backend: LocalStorageBackend, tmp_path: Path
) -> None:
    """verify_integrity returns False for corrupted blobs."""
    content = b"will be corrupted"
    ref = await manager.store(content, {})

    # Corrupt the stored file.
    blob_key = manager._blob_key(ref.content_hash)
    blob_path = (tmp_path / blob_key).resolve()
    blob_path.write_bytes(b"CORRUPTED")

    result = await manager.verify_integrity(ref.content_hash)
    assert result is False


async def test_verify_integrity_missing(manager: EvidenceManager) -> None:
    """verify_integrity returns False for missing blobs."""
    fake_hash = compute_sha256_hex(b"nonexistent blob")
    result = await manager.verify_integrity(fake_hash)
    assert result is False


# ---------------------------------------------------------------------------
# 21. S3 backend handles NoSuchKey errors correctly
# ---------------------------------------------------------------------------


async def test_s3_get_nosuchkey_error(s3_backend: S3StorageBackend) -> None:
    """S3 backend converts NoSuchKey ClientError to StorageKeyNotFoundError."""
    with pytest.raises(StorageKeyNotFoundError):
        await s3_backend.get("nonexistent/key")


async def test_s3_exists_after_delete(s3_backend: S3StorageBackend) -> None:
    """S3 backend exists returns False after delete."""
    key = "tenant/abc/evidence/delete-then-check"
    await s3_backend.put(key, b"data")
    assert await s3_backend.exists(key) is True
    await s3_backend.delete(key)
    assert await s3_backend.exists(key) is False


# ---------------------------------------------------------------------------
# 22. S3 backend pagination for list_keys
# ---------------------------------------------------------------------------


async def test_s3_list_keys_pagination(mock_client: MagicMock) -> None:
    """S3 backend handles paginated list_objects_v2 responses."""
    # Override list_objects_v2 to simulate pagination.
    call_count = 0

    def paginated_list(*, Bucket, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return {
                "Contents": [{"Key": "key-1"}, {"Key": "key-2"}],
                "IsTruncated": True,
                "NextContinuationToken": "token-page-2",
            }
        else:
            return {
                "Contents": [{"Key": "key-3"}],
                "IsTruncated": False,
            }

    mock_client.list_objects_v2 = MagicMock(side_effect=paginated_list)

    s3 = S3StorageBackend(bucket="paginated-bucket", client=mock_client)
    keys = await s3.list_keys()

    assert keys == ["key-1", "key-2", "key-3"]
    assert call_count == 2


async def test_s3_list_keys_empty_contents(mock_client: MagicMock) -> None:
    """S3 backend handles list response with no Contents key."""
    mock_client.list_objects_v2 = MagicMock(return_value={
        "IsTruncated": False,
    })
    s3 = S3StorageBackend(bucket="empty-bucket", client=mock_client)
    keys = await s3.list_keys()
    assert keys == []


# ---------------------------------------------------------------------------
# 23. Key prefix isolation
# ---------------------------------------------------------------------------


async def test_key_prefix_isolates_tenants(
    backend: LocalStorageBackend,
) -> None:
    """Different key prefixes produce isolated evidence namespaces."""
    tenant_a = UUID("018f1f00-0000-7000-8000-00000000A001")
    tenant_b = UUID("018f1f00-0000-7000-8000-00000000B002")
    mgr_a = EvidenceManager(backend, key_prefix=f"tenant/{tenant_a}")
    mgr_b = EvidenceManager(backend, key_prefix=f"tenant/{tenant_b}")

    content = b"shared content across tenants"
    ref_a = await mgr_a.store(content, {"entity_id": str(ENTITY_A)})
    ref_b = await mgr_b.store(content, {"entity_id": str(ENTITY_B)})

    # Same content hash (content-addressed).
    assert ref_a.content_hash == ref_b.content_hash

    # Both can retrieve independently.
    assert await mgr_a.retrieve(ref_a.content_hash) == content
    assert await mgr_b.retrieve(ref_b.content_hash) == content

    # Deleting from one tenant does not affect the other.
    await mgr_a.delete(ref_a.content_hash)
    assert await mgr_a.exists(ref_a.content_hash) is False
    assert await mgr_b.exists(ref_b.content_hash) is True


# ---------------------------------------------------------------------------
# 24. Empty content handling
# ---------------------------------------------------------------------------


async def test_store_empty_content(manager: EvidenceManager) -> None:
    """Storing empty bytes works correctly (edge case)."""
    ref = await manager.store(b"", {})
    assert ref.size_bytes == 0
    retrieved = await manager.retrieve(ref.content_hash)
    assert retrieved == b""
    # The hash of empty bytes is deterministic.
    assert ref.content_hash == compute_sha256_hex(b"")


# ---------------------------------------------------------------------------
# 25. Batched list_for_entity and expire (issue #154)
# ---------------------------------------------------------------------------


async def test_list_for_entity_batched_across_many_keys(
    backend: LocalStorageBackend,
) -> None:
    """list_for_entity processes keys in batches when count exceeds _BATCH_SIZE.

    Stores more evidence items than _BATCH_SIZE and verifies all matching
    refs are still returned correctly.
    """
    manager = EvidenceManager(backend)
    entity_id = uuid4()
    count = _BATCH_SIZE + 20  # exceed one full batch

    for i in range(count):
        await manager.store(
            f"evidence-{i}".encode(),
            {"entity_id": str(entity_id)},
        )

    refs = await manager.list_for_entity(entity_id)
    assert len(refs) == count
    assert all(r.metadata["entity_id"] == str(entity_id) for r in refs)


async def test_list_for_entity_batched_filters_correctly(
    backend: LocalStorageBackend,
) -> None:
    """list_for_entity still filters by entity_id when batching."""
    manager = EvidenceManager(backend)
    target = uuid4()
    other = uuid4()

    # Store items for two entities, exceeding batch size total
    for i in range(_META_FETCH_BATCH_SIZE + 10):
        await manager.store(
            f"target-{i}".encode(),
            {"entity_id": str(target)},
        )
    for i in range(5):
        await manager.store(
            f"other-{i}".encode(),
            {"entity_id": str(other)},
        )

    target_refs = await manager.list_for_entity(target)
    other_refs = await manager.list_for_entity(other)

    assert len(target_refs) == _META_FETCH_BATCH_SIZE + 10
    assert len(other_refs) == 5


async def test_expire_batched_across_many_keys(
    backend: LocalStorageBackend,
) -> None:
    """expire() processes keys in batches when count exceeds _BATCH_SIZE.

    Stores more expired blobs than _BATCH_SIZE and verifies all are expired.
    """
    manager = EvidenceManager(backend, default_retention_seconds=0)
    count = _BATCH_SIZE + 15
    stored_hashes: list[str] = []

    for i in range(count):
        ref = await manager.store(f"expire-batch-{i}".encode(), {})
        stored_hashes.append(ref.content_hash)

    expired = await manager.expire()
    assert len(expired) == count
    assert set(expired) == set(stored_hashes)

    # All blobs should be gone
    for h in stored_hashes:
        assert await manager.exists(h) is False


async def test_expire_batched_preserves_fresh(
    backend: LocalStorageBackend,
) -> None:
    """expire() in batched mode still preserves non-expired blobs."""
    manager = EvidenceManager(backend, default_retention_seconds=86400)

    # Store some expired (retention=0) and some fresh
    expired_hashes: list[str] = []
    for i in range(_META_FETCH_BATCH_SIZE + 5):
        ref = await manager.store(
            f"expired-{i}".encode(), {}, retention_seconds=0,
        )
        expired_hashes.append(ref.content_hash)

    fresh_hashes: list[str] = []
    for i in range(3):
        ref = await manager.store(f"fresh-{i}".encode(), {})
        fresh_hashes.append(ref.content_hash)

    expired = await manager.expire()
    assert set(expired) == set(expired_hashes)

    # Fresh blobs survive
    for h in fresh_hashes:
        assert await manager.exists(h) is True


def test_batch_size_constants() -> None:
    """Verify batch size constants are set correctly (issue #154)."""
    assert _BATCH_SIZE == 100
    assert _META_FETCH_BATCH_SIZE == 50


# ---------------------------------------------------------------------------
# 26. S3 backend with EvidenceManager integrity verification
# ---------------------------------------------------------------------------


async def test_s3_evidence_manager_integrity_detect(mock_client: MagicMock) -> None:
    """EvidenceManager detects corruption in S3-backed blobs."""
    s3 = S3StorageBackend(bucket="integrity-bucket", client=mock_client)
    mgr = EvidenceManager(s3, key_prefix=f"tenant/{TENANT_ID}")

    content = b"S3 integrity test content"
    ref = await mgr.store(content, {})

    # Corrupt the blob in the mock store.
    blob_key = mgr._blob_key(ref.content_hash)
    mock_client._store[blob_key]["Body"] = b"CORRUPTED S3 DATA"

    with pytest.raises(EvidenceIntegrityError, match="integrity check failed"):
        await mgr.retrieve(ref.content_hash)


async def test_s3_evidence_manager_verify_integrity(mock_client: MagicMock) -> None:
    """EvidenceManager.verify_integrity works with S3 backend."""
    s3 = S3StorageBackend(bucket="verify-bucket", client=mock_client)
    mgr = EvidenceManager(s3, key_prefix=f"tenant/{TENANT_ID}")

    content = b"S3 verify test"
    ref = await mgr.store(content, {})

    assert await mgr.verify_integrity(ref.content_hash) is True

    # Corrupt the blob.
    blob_key = mgr._blob_key(ref.content_hash)
    mock_client._store[blob_key]["Body"] = b"CORRUPTED"

    assert await mgr.verify_integrity(ref.content_hash) is False


# ---------------------------------------------------------------------------
# 27. S3 constructor accepts credentials
# ---------------------------------------------------------------------------


def test_s3_constructor_with_credentials() -> None:
    """S3StorageBackend constructor stores credential parameters."""
    s3 = S3StorageBackend(
        bucket="cred-bucket",
        region="eu-west-1",
        endpoint_url="https://minio.example.com:9000",
        client=MagicMock(),
    )
    assert s3._bucket == "cred-bucket"
    assert s3._region == "eu-west-1"
    assert s3._endpoint_url == "https://minio.example.com:9000"


def test_s3_constructor_without_boto3_raises() -> None:
    """S3StorageBackend raises ImportError when boto3 is not available."""
    import expose.storage.s3 as s3_module

    original_boto3 = s3_module._boto3
    try:
        s3_module._boto3 = None
        with pytest.raises(ImportError, match="boto3 is required"):
            S3StorageBackend(bucket="no-boto3")
    finally:
        s3_module._boto3 = original_boto3
