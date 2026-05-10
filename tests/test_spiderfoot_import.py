"""Tests for the SpiderFoot configuration importer (W1.F).

The fixture builds a synthetic SpiderFoot ``spiderfoot.db`` matching the
schema seen in production SpiderFoot installations:

    CREATE TABLE tbl_config (
        scope VARCHAR NOT NULL,
        opt   VARCHAR NOT NULL,
        val   VARCHAR NOT NULL,
        PRIMARY KEY (scope, opt)
    )

We populate it with a representative mix:

- Mapped credentials (``sfp_shodan``, ``sfp_securitytrails``).
- An unmapped-but-known credential (``sfp_virustotal`` — in the map but
  ``collector_id`` is ``None`` because EXPOSE has no VT collector yet).
- A truly unknown SpiderFoot module (``sfp_someunknownmodule``) — falls
  through to the ``unmapped.*`` namespace.
- A non-credential ``GLOBAL`` row — must be excluded.
- A non-credential ``opt`` (``_internal_state``) on a known module — must
  be excluded by the credential-opts filter.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from uuid import UUID

import pytest

from expose.import_ import (
    SPIDERFOOT_MODULE_MAP,
    ImportedKey,
    SpiderFootImporter,
)
from expose.secrets import InMemoryBackend

TENANT_FOR_IMPORT = UUID("018f1f00-0000-7000-8000-00000000F001")


@pytest.fixture
def synthetic_spiderfoot_db(tmp_path: Path) -> Path:
    """Build a synthetic spiderfoot.db file with a representative row mix.

    Row inventory (7 rows total):

    - ``sfp_shodan / api_key``         — mapped to collector ``shodan-iwide``.
    - ``sfp_securitytrails / api_key`` — mapped to ``pdns-securitytrails``.
    - ``sfp_virustotal / api_key``     — known module, ``collector_id=None``
      (unmapped per current EXPOSE collector roster).
    - ``sfp_someunknownmodule / api_key`` — truly unknown SpiderFoot module
      (falls through to ``unmapped.*`` namespace).
    - ``sfp_greynoise / api_key``      — known module, ``collector_id=None``.
    - ``GLOBAL / _log_level``          — non-``sfp_*`` scope; excluded.
    - ``sfp_dnsdb / _internal_state``  — ``sfp_*`` scope but non-credential
      opt; excluded.
    """
    db_path = tmp_path / "spiderfoot.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE tbl_config ("
        "scope VARCHAR NOT NULL, "
        "opt VARCHAR NOT NULL, "
        "val VARCHAR NOT NULL, "
        "PRIMARY KEY (scope, opt))"
    )
    conn.executemany(
        "INSERT INTO tbl_config (scope, opt, val) VALUES (?, ?, ?)",
        [
            ("sfp_shodan", "api_key", "TESTKEY_SHODAN_001"),
            ("sfp_securitytrails", "api_key", "TESTKEY_ST_002"),
            ("sfp_virustotal", "api_key", "TESTKEY_VT_003"),
            ("sfp_someunknownmodule", "api_key", "TESTKEY_UNKNOWN_004"),
            ("sfp_greynoise", "api_key", "TESTKEY_GN_005"),
            ("GLOBAL", "_log_level", "INFO"),
            ("sfp_dnsdb", "_internal_state", "1"),
        ],
    )
    conn.commit()
    conn.close()
    return db_path


@pytest.fixture
def importer(synthetic_spiderfoot_db: Path) -> SpiderFootImporter:
    """A fresh SpiderFootImporter pointed at the synthetic DB."""
    return SpiderFootImporter(synthetic_spiderfoot_db)


@pytest.fixture
def caplog_debug(caplog: pytest.LogCaptureFixture) -> Iterator[pytest.LogCaptureFixture]:
    """Capture DEBUG-level logs from the importer module."""
    with caplog.at_level(logging.DEBUG, logger="expose.import_.spiderfoot"):
        yield caplog


def test_read_config_returns_all_rows(importer: SpiderFootImporter) -> None:
    """read_config returns every tbl_config row, including non-credential noise."""
    rows = importer.read_config()
    assert len(rows) == 7
    # Sanity-check that scopes/opts are surfaced verbatim — confirms NULL
    # coercion didn't accidentally drop anything.
    scopes = {scope for (scope, _opt, _val) in rows}
    assert "GLOBAL" in scopes
    assert "sfp_shodan" in scopes
    assert "sfp_dnsdb" in scopes


def test_extract_module_keys_filters_to_sfp_prefix(importer: SpiderFootImporter) -> None:
    """The GLOBAL row must be excluded; only sfp_* scopes survive the filter."""
    keys = importer.extract_module_keys()
    modules = {k.spiderfoot_module for k in keys}
    assert "GLOBAL" not in modules
    assert all(m.startswith("sfp_") for m in modules)


def test_extract_module_keys_filters_to_credential_opts(
    importer: SpiderFootImporter,
) -> None:
    """The sfp_dnsdb / _internal_state row must be excluded — opt is non-credential."""
    keys = importer.extract_module_keys()
    # Even though sfp_dnsdb is a known SpiderFoot module, the _internal_state
    # opt is not a credential and must NOT appear in the result.
    assert all(k.spiderfoot_opt in SpiderFootImporter.CREDENTIAL_OPT_NAMES for k in keys)
    pairs = {(k.spiderfoot_module, k.spiderfoot_opt) for k in keys}
    assert ("sfp_dnsdb", "_internal_state") not in pairs


def test_extract_module_keys_classifies_mapping(importer: SpiderFootImporter) -> None:
    """Mapped modules get their collector_id; unknown modules get None."""
    keys_by_module = {k.spiderfoot_module: k for k in importer.extract_module_keys()}

    # Mapped: sfp_shodan resolves to the canonical EXPOSE collector_id.
    assert keys_by_module["sfp_shodan"].collector_id == "shodan-iwide"
    assert SPIDERFOOT_MODULE_MAP["sfp_shodan"] == "shodan-iwide"

    # Mapped: sfp_securitytrails too.
    assert keys_by_module["sfp_securitytrails"].collector_id == "pdns-securitytrails"

    # Known module, no EXPOSE collector yet — collector_id is None.
    assert keys_by_module["sfp_virustotal"].collector_id is None
    assert SPIDERFOOT_MODULE_MAP["sfp_virustotal"] is None
    assert keys_by_module["sfp_greynoise"].collector_id is None

    # Truly-unknown module (not in the map at all) — also None.
    assert keys_by_module["sfp_someunknownmodule"].collector_id is None
    assert "sfp_someunknownmodule" not in SPIDERFOOT_MODULE_MAP


def test_extract_module_keys_secret_key_naming(importer: SpiderFootImporter) -> None:
    """Mapped -> collector.<id>.<opt>; unmapped -> unmapped.<sfp_module>.<opt>."""
    keys_by_module = {k.spiderfoot_module: k for k in importer.extract_module_keys()}

    # The literal RHS in each assert below is the EXPOSE secret-store *key*
    # (the logical address into the secrets backend), not a credential value.
    # ruff S105's "hardcoded password" heuristic fires on the surrounding
    # ``secret_key`` attribute name — suppress per-line.

    # Mapped namespace.
    assert keys_by_module["sfp_shodan"].secret_key == "collector.shodan-iwide.api_key"  # noqa: S105
    assert (
        keys_by_module["sfp_securitytrails"].secret_key
        == "collector.pdns-securitytrails.api_key"  # noqa: S105
    )

    # Unmapped namespace — both for known-but-uncollected and truly-unknown.
    assert keys_by_module["sfp_virustotal"].secret_key == "unmapped.sfp_virustotal.api_key"  # noqa: S105
    assert (
        keys_by_module["sfp_someunknownmodule"].secret_key
        == "unmapped.sfp_someunknownmodule.api_key"  # noqa: S105
    )
    assert keys_by_module["sfp_greynoise"].secret_key == "unmapped.sfp_greynoise.api_key"  # noqa: S105


async def test_import_to_backend_writes_all(importer: SpiderFootImporter) -> None:
    """All 5 surviving credentials land in the backend under the right keys."""
    backend = InMemoryBackend()
    summary = await importer.import_to_backend(
        backend=backend,
        tenant_id=TENANT_FOR_IMPORT,
    )

    assert summary.api_key_rows == 5

    # Each value must round-trip exactly.
    assert (
        await backend.get(tenant_id=TENANT_FOR_IMPORT, key="collector.shodan-iwide.api_key")
        == "TESTKEY_SHODAN_001"
    )
    assert (
        await backend.get(
            tenant_id=TENANT_FOR_IMPORT, key="collector.pdns-securitytrails.api_key"
        )
        == "TESTKEY_ST_002"
    )
    assert (
        await backend.get(
            tenant_id=TENANT_FOR_IMPORT, key="unmapped.sfp_virustotal.api_key"
        )
        == "TESTKEY_VT_003"
    )
    assert (
        await backend.get(
            tenant_id=TENANT_FOR_IMPORT, key="unmapped.sfp_someunknownmodule.api_key"
        )
        == "TESTKEY_UNKNOWN_004"
    )
    assert (
        await backend.get(
            tenant_id=TENANT_FOR_IMPORT, key="unmapped.sfp_greynoise.api_key"
        )
        == "TESTKEY_GN_005"
    )

    # And the backend's tenant scope is exact: 5 keys live under our tenant.
    keys = await backend.list_keys(tenant_id=TENANT_FOR_IMPORT)
    assert len(keys) == 5


async def test_import_to_backend_redacts_in_logs(
    importer: SpiderFootImporter,
    caplog_debug: pytest.LogCaptureFixture,
) -> None:
    """No log record at any level may contain a TESTKEY_ substring."""
    backend = InMemoryBackend()
    await importer.import_to_backend(
        backend=backend,
        tenant_id=TENANT_FOR_IMPORT,
    )

    # Build the full text of every captured record across every level.
    every_field_text = []
    for record in caplog_debug.records:
        every_field_text.append(record.getMessage())
        # Include every extra-attribute value too — extras are how we feed
        # structured fields into the logger and are the most likely place a
        # secret could leak if redaction broke.
        for value in record.__dict__.values():
            every_field_text.append(repr(value))
    haystack = "\n".join(every_field_text)

    # Every TESTKEY_* sentinel from the fixture must be absent.
    forbidden_fragments = [
        "TESTKEY_SHODAN_001",
        "TESTKEY_ST_002",
        "TESTKEY_VT_003",
        "TESTKEY_UNKNOWN_004",
        "TESTKEY_GN_005",
        # Stronger blanket assertion: NO TESTKEY_ substring at all.
        "TESTKEY_",
    ]
    for fragment in forbidden_fragments:
        assert fragment not in haystack, (
            f"Secret value substring {fragment!r} appeared in log output — redaction broke."
        )

    # Sanity: the redaction placeholder itself IS present at DEBUG, proving
    # the test actually exercised the per-key DEBUG log line.
    assert "<redacted>" in haystack


async def test_import_to_backend_returns_summary_counts(
    importer: SpiderFootImporter,
) -> None:
    """ImportSummary aggregates counts: total=7, api_key=5, mapped=2, unmapped=3."""
    backend = InMemoryBackend()
    summary = await importer.import_to_backend(
        backend=backend,
        tenant_id=TENANT_FOR_IMPORT,
    )

    assert summary.total_rows_read == 7
    assert summary.api_key_rows == 5
    # Mapped: sfp_shodan + sfp_securitytrails (the only two with non-None
    # entries in SPIDERFOOT_MODULE_MAP among the rows that survived filtering).
    # sfp_virustotal and sfp_greynoise are in the map but with collector_id=None
    # (i.e., known but no EXPOSE collector yet) so they count as unmapped.
    assert summary.mapped_count == 2
    assert summary.unmapped_count == 3
    # Skipped: 7 total - 5 surviving credential rows = 2 (the GLOBAL row and
    # the sfp_dnsdb / _internal_state row).
    assert summary.skipped_count == 2

    # Round-trip: imported_keys length matches api_key_rows.
    assert len(summary.imported_keys) == summary.api_key_rows
    # And every entry is the expected dataclass.
    for record in summary.imported_keys:
        assert isinstance(record, ImportedKey)
