"""Tests for the object storage backend abstraction (issue #9).

Coverage:

1.  put + get round-trip returns data verbatim.
2.  get on a nonexistent key raises :class:`StorageKeyNotFoundError`.
3.  exists returns ``True`` after put.
4.  exists returns ``False`` for a missing key.
5.  delete removes the key (verified by exists + get).
6.  delete returns ``False`` for a missing key.
7.  list_keys returns stored keys.
8.  list_keys with prefix filters correctly.
9.  Key path includes tenant_id namespace (tenant isolation).
10. Binary round-trip preserves content exactly (non-UTF8 data).
11. S3 stub raises :exc:`NotImplementedError` on every method.
12. :class:`StorageBackend` ABC cannot be instantiated directly.
13. put returns a URI string.
14. Overwrite semantics: second put replaces data.

These tests use :class:`LocalStorageBackend` via ``tmp_path`` so no
external services are required.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest

from expose.storage import (
    LocalStorageBackend,
    S3StorageBackend,
    StorageBackend,
    StorageKeyNotFoundError,
)

# Synthetic tenant UUIDs matching the project convention.
TENANT_A = UUID("018f1f00-0000-7000-8000-00000000A001")
TENANT_B = UUID("018f1f00-0000-7000-8000-00000000B002")


@pytest.fixture
def backend(tmp_path: Path) -> LocalStorageBackend:
    """Fresh local storage backend per test (no cross-test bleed)."""
    return LocalStorageBackend(root=tmp_path)


# ---------------------------------------------------------------------------
# 1. put + get round-trip
# ---------------------------------------------------------------------------
async def test_put_then_get_returns_data(backend: LocalStorageBackend) -> None:
    """Data stored via put is returned verbatim by get."""
    key = f"tenant/{TENANT_A}/evidence/abc123"
    data = b"raw HTTP response body"
    await backend.put(key, data)
    got = await backend.get(key)
    assert got == data


# ---------------------------------------------------------------------------
# 2. get nonexistent key raises StorageKeyNotFoundError
# ---------------------------------------------------------------------------
async def test_get_missing_raises(backend: LocalStorageBackend) -> None:
    """get on an absent key raises StorageKeyNotFoundError (also KeyError)."""
    with pytest.raises(StorageKeyNotFoundError):
        await backend.get("tenant/does-not-exist/evidence/none")
    # StorageKeyNotFoundError must subclass KeyError for broad except paths.
    with pytest.raises(KeyError):
        await backend.get("tenant/does-not-exist/evidence/none")


# ---------------------------------------------------------------------------
# 3. exists returns True after put
# ---------------------------------------------------------------------------
async def test_exists_after_put(backend: LocalStorageBackend) -> None:
    """exists returns True for a key that has been stored."""
    key = f"tenant/{TENANT_A}/evidence/def456"
    await backend.put(key, b"cert PEM data")
    assert await backend.exists(key) is True


# ---------------------------------------------------------------------------
# 4. exists returns False for missing key
# ---------------------------------------------------------------------------
async def test_exists_missing(backend: LocalStorageBackend) -> None:
    """exists returns False for a key that has never been stored."""
    assert await backend.exists("tenant/missing/evidence/nope") is False


# ---------------------------------------------------------------------------
# 5. delete removes the key
# ---------------------------------------------------------------------------
async def test_delete_removes_key(backend: LocalStorageBackend) -> None:
    """After delete, exists returns False and get raises."""
    key = f"tenant/{TENANT_A}/evidence/ghi789"
    await backend.put(key, b"DNS response")
    result = await backend.delete(key)
    assert result is True
    assert await backend.exists(key) is False
    with pytest.raises(StorageKeyNotFoundError):
        await backend.get(key)


# ---------------------------------------------------------------------------
# 6. delete returns False for missing key
# ---------------------------------------------------------------------------
async def test_delete_missing_returns_false(backend: LocalStorageBackend) -> None:
    """Deleting a nonexistent key returns False (idempotent, no error)."""
    result = await backend.delete("tenant/never-stored/evidence/none")
    assert result is False


# ---------------------------------------------------------------------------
# 7. list_keys returns stored keys
# ---------------------------------------------------------------------------
async def test_list_keys_returns_stored(backend: LocalStorageBackend) -> None:
    """list_keys returns all keys that have been stored."""
    keys = [
        f"tenant/{TENANT_A}/evidence/aaa",
        f"tenant/{TENANT_A}/evidence/bbb",
        f"tenant/{TENANT_A}/artifacts/run001.json",
    ]
    for k in keys:
        await backend.put(k, b"payload")
    listed = await backend.list_keys()
    assert sorted(listed) == sorted(keys)


# ---------------------------------------------------------------------------
# 8. list_keys with prefix filters correctly
# ---------------------------------------------------------------------------
async def test_list_keys_prefix_filter(backend: LocalStorageBackend) -> None:
    """list_keys with a prefix returns only matching keys."""
    evidence_key = f"tenant/{TENANT_A}/evidence/aaa"
    artifact_key = f"tenant/{TENANT_A}/artifacts/run001.json"
    await backend.put(evidence_key, b"evidence")
    await backend.put(artifact_key, b"artifact")

    evidence_keys = await backend.list_keys(prefix=f"tenant/{TENANT_A}/evidence")
    assert evidence_keys == [evidence_key]

    artifact_keys = await backend.list_keys(prefix=f"tenant/{TENANT_A}/artifacts")
    assert artifact_keys == [artifact_key]


# ---------------------------------------------------------------------------
# 9. Key path includes tenant_id namespace
# ---------------------------------------------------------------------------
async def test_tenant_namespace_isolation(backend: LocalStorageBackend) -> None:
    """Keys scoped to different tenants are isolated in list_keys."""
    key_a = f"tenant/{TENANT_A}/evidence/shared_hash"
    key_b = f"tenant/{TENANT_B}/evidence/shared_hash"
    await backend.put(key_a, b"tenant A data")
    await backend.put(key_b, b"tenant B data")

    a_keys = await backend.list_keys(prefix=f"tenant/{TENANT_A}")
    b_keys = await backend.list_keys(prefix=f"tenant/{TENANT_B}")

    assert a_keys == [key_a]
    assert b_keys == [key_b]

    # Data is independently retrievable.
    assert await backend.get(key_a) == b"tenant A data"
    assert await backend.get(key_b) == b"tenant B data"


# ---------------------------------------------------------------------------
# 10. Binary round-trip preserves content exactly
# ---------------------------------------------------------------------------
async def test_binary_round_trip(backend: LocalStorageBackend) -> None:
    """Non-UTF8 binary data survives the put/get round-trip unchanged."""
    key = f"tenant/{TENANT_A}/evidence/binary_blob"
    # Construct data with every byte value 0x00..0xFF.
    data = bytes(range(256))
    await backend.put(key, data)
    got = await backend.get(key)
    assert got == data
    assert len(got) == 256


# ---------------------------------------------------------------------------
# 11. S3 stub raises NotImplementedError
# ---------------------------------------------------------------------------
async def test_s3_stub_raises() -> None:
    """Every method on the S3 stub raises NotImplementedError."""
    s3 = S3StorageBackend(bucket="test-bucket")
    with pytest.raises(NotImplementedError, match="S3 backend not yet implemented"):
        await s3.put("key", b"data")
    with pytest.raises(NotImplementedError, match="S3 backend not yet implemented"):
        await s3.get("key")
    with pytest.raises(NotImplementedError, match="S3 backend not yet implemented"):
        await s3.exists("key")
    with pytest.raises(NotImplementedError, match="S3 backend not yet implemented"):
        await s3.delete("key")
    with pytest.raises(NotImplementedError, match="S3 backend not yet implemented"):
        await s3.list_keys()


# ---------------------------------------------------------------------------
# 12. StorageBackend ABC cannot be instantiated
# ---------------------------------------------------------------------------
async def test_abc_cannot_instantiate() -> None:
    """Attempting to instantiate StorageBackend directly raises TypeError."""
    with pytest.raises(TypeError, match="Can't instantiate abstract class"):
        StorageBackend()  # type: ignore[abstract]


# ---------------------------------------------------------------------------
# 13. put returns a URI string
# ---------------------------------------------------------------------------
async def test_put_returns_uri(backend: LocalStorageBackend) -> None:
    """put returns a URI string referencing the stored object."""
    key = f"tenant/{TENANT_A}/evidence/uri_test"
    uri = await backend.put(key, b"data for URI test")
    assert isinstance(uri, str)
    assert uri.startswith("file://")
    assert "uri_test" in uri


# ---------------------------------------------------------------------------
# 14. Overwrite semantics: second put replaces data
# ---------------------------------------------------------------------------
async def test_put_overwrites(backend: LocalStorageBackend) -> None:
    """A second put to the same key replaces the stored data."""
    key = f"tenant/{TENANT_A}/evidence/overwrite_test"
    await backend.put(key, b"original")
    await backend.put(key, b"replacement")
    got = await backend.get(key)
    assert got == b"replacement"
