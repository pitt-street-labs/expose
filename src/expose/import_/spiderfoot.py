"""Read API keys from a SpiderFoot SQLite database into EXPOSE's secrets backend.

SpiderFoot (smicallef/spiderfoot) stores per-module configuration — including
API keys for the OSINT services it queries — in a SQLite database. The schema
relevant to credentials is::

    CREATE TABLE tbl_config (
        scope VARCHAR NOT NULL,
        opt   VARCHAR NOT NULL,
        val   VARCHAR NOT NULL,
        PRIMARY KEY (scope, opt)
    )

Where ``scope='sfp_<module>'`` identifies the SpiderFoot module (``sfp_shodan``,
``sfp_securitytrails``, etc.) and ``opt`` identifies the individual setting
within that module — typically ``api_key`` for credentials but with variants
(``key``, ``token``, etc.) for older modules. The ``GLOBAL`` scope holds
SpiderFoot's own settings (log level, output paths) and is excluded from the
import.

This importer:

1. Connects to the SQLite file (read-only).
2. Reads all rows from ``tbl_config``.
3. Filters to ``scope LIKE 'sfp_%'`` AND ``opt`` in :attr:`CREDENTIAL_OPT_NAMES`.
4. Classifies each surviving row against :data:`SPIDERFOOT_MODULE_MAP` —
   mapped rows get a stable EXPOSE secret key (``collector.<id>.<opt>``);
   unmapped rows get a fallback (``unmapped.<sfp_module>.<opt>``) so the
   operator can review and re-target manually.
5. Writes each :class:`ImportedKey` into the configured
   :class:`expose.secrets.SecretsBackend` under the operator's tenant.

Logging is structured (stdlib ``logging`` for now; structlog wiring lives in
``expose.observability`` and lands separately). Per the project hard rule, no
log statement at ANY level includes the secret value — the per-key DEBUG log
substitutes the literal string ``<redacted>``.

CLI wiring is W4.A's responsibility. This module only exposes the pure-Python
class so unit tests don't need a CLI runner.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from collections.abc import Sequence
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar
from uuid import UUID

from expose.secrets.backend import SecretsBackend

logger = logging.getLogger(__name__)

# === Module map ==============================================================
# SpiderFoot module name -> EXPOSE collector_id (or None when EXPOSE has no
# matching collector yet, in which case the key is imported under an
# ``unmapped.*`` slot for operator review).
#
# Entries with ``None`` are intentional: the credential is still WORTH importing
# (operator explicitly registered it with a third-party service) but EXPOSE
# does not currently have a collector that consumes it. As Tier 1/2 collectors
# land sprint-by-sprint, ``None`` entries will flip to mapped collector ids.
SPIDERFOOT_MODULE_MAP: dict[str, str | None] = {
    # Tier 2 paid services that EXPOSE has matching collectors for today.
    "sfp_shodan": "shodan-iwide",
    "sfp_securitytrails": "pdns-securitytrails",
    "sfp_passivetotal": "pdns-passivetotal",
    "sfp_zetalytics": "pdns-zetalytics",
    # Tier 2 paid services with matching EXPOSE collectors (added post-Sprint 2).
    "sfp_censys": "scan-censys",
    "sfp_binaryedge": "scan-binaryedge",
    # Tier 2 services on the EXPOSE roadmap but no collector yet.
    "sfp_virustotal": None,
    "sfp_dnsdb": None,
    "sfp_circl": None,
    "sfp_greynoise": None,
    "sfp_urlscan": None,
    "sfp_zoomeye": None,
    "sfp_intelx": None,
    "sfp_ipinfo": None,
    "sfp_fullhunt": None,
    "sfp_leakix": None,
    # Common SpiderFoot OSINT modules with API keys that EXPOSE may add later.
    "sfp_alienvault": None,
    "sfp_hunter": None,
    "sfp_haveibeenpwned": None,
    "sfp_whoxy": None,
    "sfp_riskiq": None,
    "sfp_spyse": None,
    "sfp_pulsedive": None,
    "sfp_threatcrowd": None,
    "sfp_threatminer": None,
    "sfp_emergingthreats": None,
}


# === Result types ============================================================
@dataclass(frozen=True)
class ImportedKey:
    """One credential row promoted from SpiderFoot to EXPOSE.

    Attributes:
        spiderfoot_module: The SpiderFoot ``scope`` value (``sfp_shodan``).
        spiderfoot_opt: The SpiderFoot ``opt`` value (typically ``api_key``).
        collector_id: The mapped EXPOSE collector_id, or ``None`` when no
            mapping exists in :data:`SPIDERFOOT_MODULE_MAP`.
        secret_key: The key under which the value is stored in the EXPOSE
            secrets backend. Convention:

            * Mapped:   ``collector.<collector_id>.<opt>``
            * Unmapped: ``unmapped.<sfp_module>.<opt>``

    The convention keeps mapped credentials in a flat namespace the
    dispatcher already knows how to fetch (collector code calls
    ``backend.get(tenant_id=..., key=f"collector.{self.collector_id}.api_key")``)
    while unmapped credentials land in a separate prefix the operator can
    enumerate via ``backend.list_keys`` for review.
    """

    spiderfoot_module: str
    spiderfoot_opt: str
    collector_id: str | None
    secret_key: str


@dataclass(frozen=True)
class ImportSummary:
    """Aggregate result of one importer run.

    Attributes:
        total_rows_read: Every row read from ``tbl_config`` (including
            non-credential and non-``sfp_*`` rows).
        api_key_rows: Rows that survived the
            ``sfp_*`` + :attr:`SpiderFootImporter.CREDENTIAL_OPT_NAMES`
            filters — these are the candidate credentials.
        mapped_count: Of ``api_key_rows``, how many had a non-``None`` entry
            in :data:`SPIDERFOOT_MODULE_MAP`.
        unmapped_count: Of ``api_key_rows``, how many fell through to the
            ``unmapped.*`` namespace.
        skipped_count: Rows skipped for non-credential or empty-value reasons
            (``api_key_rows = total_rows_read - skipped_count``).
        imported_keys: Per-key records describing each write. Does NOT include
            the secret value itself (so the summary can be safely logged).
    """

    total_rows_read: int
    api_key_rows: int
    mapped_count: int
    unmapped_count: int
    skipped_count: int
    imported_keys: list[ImportedKey]


# === The importer ============================================================
class SpiderFootImporter:
    """Read SpiderFoot's SQLite ``tbl_config`` and import credentials.

    Construction is cheap (does not open the database). The actual SQLite
    connection is made on-demand inside :meth:`read_config`, scoped via a
    context manager so the file is never left open longer than the read.

    Asyncio note: SQLite I/O is blocking; :meth:`import_to_backend` runs the
    SQLite read on the default executor via :func:`asyncio.to_thread` so the
    event loop is not blocked while the (typically tiny) database file is
    parsed. The :class:`SecretsBackend` writes are awaited normally.
    """

    # Set of SpiderFoot ``opt`` values that are interpreted as credential
    # material. Unrecognized opts (settings, internal flags, search caps) are
    # filtered out so we never accidentally import a non-secret as a secret.
    #
    # SpiderFoot module authors are inconsistent: ``api_key`` is the modern
    # convention, but ``key`` survives in older modules (e.g., earlier sfp_*
    # forks) and ``apikey`` / ``token`` / ``secret`` show up in third-party
    # forks. ``username`` / ``password`` cover the (rarer) basic-auth modules.
    # We intentionally bias toward inclusion: a false positive here gets
    # reviewed by the operator (it appears in ``backend.list_keys``); a false
    # negative loses a credential the operator wanted.
    CREDENTIAL_OPT_NAMES: ClassVar[set[str]] = {
        "api_key",
        "api_id",
        "api_secret",
        "key",
        "apikey",
        "token",
        "secret",
        "username",
        "password",
    }

    def __init__(self, sqlite_path: Path) -> None:
        """Hold the path to the SpiderFoot SQLite database (no I/O at init).

        Args:
            sqlite_path: Absolute path to the SpiderFoot ``spiderfoot.db``
                file. Existence is NOT checked at construction so callers can
                construct the importer in code paths separate from where the
                user supplies the path; existence is enforced when
                :meth:`read_config` runs.
        """
        self._sqlite_path = sqlite_path

    @property
    def sqlite_path(self) -> Path:
        """The configured SpiderFoot SQLite path (read-only)."""
        return self._sqlite_path

    def read_config(self) -> Sequence[tuple[str, str, str]]:
        """Read every row from ``tbl_config``.

        Returns:
            A sequence of ``(scope, opt, val)`` tuples preserving the
            database's row order. NULL ``val`` entries are coerced to
            empty strings so downstream filtering works uniformly; the
            empty-value filter in :meth:`extract_module_keys` then drops them.

        Raises:
            sqlite3.OperationalError: When the database file does not exist
                or the ``tbl_config`` table is missing.
        """
        # ``uri=True`` lets us request read-only mode via ``mode=ro``; this
        # protects against accidentally mutating the operator's source DB.
        # ``immutable=1`` further hints SQLite that no concurrent writer will
        # appear, enabling some optimisations.
        uri = f"file:{self._sqlite_path}?mode=ro&immutable=1"
        with (
            closing(sqlite3.connect(uri, uri=True)) as conn,
            closing(conn.cursor()) as cur,
        ):
            cur.execute("SELECT scope, opt, val FROM tbl_config")
            rows = cur.fetchall()
        # Coerce NULL -> "" up-front so the rest of the pipeline can rely on
        # ``str``-typed values without scattered ``or ""`` patches.
        return [(scope, opt, val if val is not None else "") for (scope, opt, val) in rows]

    def extract_module_keys(self) -> Sequence[ImportedKey]:
        """Read the database and return the classified credential rows.

        Returns:
            Sequence of :class:`ImportedKey` records, one per row that
            survives the ``scope LIKE 'sfp_%'`` AND
            ``opt in CREDENTIAL_OPT_NAMES`` AND non-empty-``val`` filters.
            Mapping decisions follow :data:`SPIDERFOOT_MODULE_MAP`.

        Note:
            This method opens the SQLite file. To inspect the unfiltered rows
            (e.g., for debugging), call :meth:`read_config` directly.
        """
        rows = self.read_config()
        out: list[ImportedKey] = []
        for scope, opt, val in rows:
            if not scope.startswith("sfp_"):
                continue
            if opt not in self.CREDENTIAL_OPT_NAMES:
                continue
            if not val:
                # Skip empty-string credentials — the operator never set a key
                # for this module; importing an empty value would just produce
                # confusing auth failures later.
                continue
            collector_id = SPIDERFOOT_MODULE_MAP.get(scope)
            secret_key = (
                f"collector.{collector_id}.{opt}"
                if collector_id is not None
                else f"unmapped.{scope}.{opt}"
            )
            out.append(
                ImportedKey(
                    spiderfoot_module=scope,
                    spiderfoot_opt=opt,
                    collector_id=collector_id,
                    secret_key=secret_key,
                )
            )
        return out

    async def import_to_backend(
        self,
        *,
        backend: SecretsBackend,
        tenant_id: UUID,
    ) -> ImportSummary:
        """Read, classify, and write all credential rows to ``backend``.

        Args:
            backend: Target :class:`SecretsBackend` instance. Writes use
                ``backend.set`` (overwrite-on-conflict) so re-running the
                importer is idempotent and safe.
            tenant_id: Tenant under which to scope all writes. Per ADR-007
                tenant context is explicit at every call boundary.

        Returns:
            :class:`ImportSummary` aggregating row counts and per-key records
            (without secret values). Safe to log at INFO.

        Logging:
            INFO: ``spiderfoot_import_started`` (path) and
            ``spiderfoot_import_completed`` (summary minus the actual values).
            DEBUG: per-key trace with ``value=<redacted>`` placeholder.
        """
        logger.info(
            "spiderfoot_import_started",
            extra={
                "sqlite_path": str(self._sqlite_path),
                "tenant_id": str(tenant_id),
            },
        )

        # Run the blocking SQLite work off the event loop. ``read_config``
        # opens, reads, closes — fast for typical config DBs but still I/O.
        rows = await asyncio.to_thread(self.read_config)

        api_key_records: list[tuple[ImportedKey, str]] = []
        for scope, opt, val in rows:
            if not scope.startswith("sfp_"):
                continue
            if opt not in self.CREDENTIAL_OPT_NAMES:
                continue
            if not val:
                continue
            collector_id = SPIDERFOOT_MODULE_MAP.get(scope)
            secret_key = (
                f"collector.{collector_id}.{opt}"
                if collector_id is not None
                else f"unmapped.{scope}.{opt}"
            )
            record = ImportedKey(
                spiderfoot_module=scope,
                spiderfoot_opt=opt,
                collector_id=collector_id,
                secret_key=secret_key,
            )
            api_key_records.append((record, val))

        # Write through the abstract backend — never log ``val`` here or below.
        for record, val in api_key_records:
            logger.debug(
                "spiderfoot_import_key",
                extra={
                    "spiderfoot_module": record.spiderfoot_module,
                    "spiderfoot_opt": record.spiderfoot_opt,
                    "collector_id": record.collector_id,
                    "secret_key": record.secret_key,
                    "value": "<redacted>",
                },
            )
            await backend.set(
                tenant_id=tenant_id,
                key=record.secret_key,
                value=val,
            )

        imported_keys = [record for (record, _val) in api_key_records]
        mapped_count = sum(1 for k in imported_keys if k.collector_id is not None)
        unmapped_count = len(imported_keys) - mapped_count
        summary = ImportSummary(
            total_rows_read=len(rows),
            api_key_rows=len(imported_keys),
            mapped_count=mapped_count,
            unmapped_count=unmapped_count,
            skipped_count=len(rows) - len(imported_keys),
            imported_keys=imported_keys,
        )

        logger.info(
            "spiderfoot_import_completed",
            extra={
                "sqlite_path": str(self._sqlite_path),
                "tenant_id": str(tenant_id),
                "total_rows_read": summary.total_rows_read,
                "api_key_rows": summary.api_key_rows,
                "mapped_count": summary.mapped_count,
                "unmapped_count": summary.unmapped_count,
                "skipped_count": summary.skipped_count,
            },
        )

        return summary


__all__ = [
    "SPIDERFOOT_MODULE_MAP",
    "ImportSummary",
    "ImportedKey",
    "SpiderFootImporter",
]
