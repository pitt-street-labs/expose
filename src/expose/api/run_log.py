"""In-memory run log accumulator and API endpoint for scan progress streaming.

Provides structured log capture from the pipeline executor and dispatcher,
stored in-memory keyed by run_id. The dashboard polls the log endpoint to
display real-time scan progress in a terminal-style panel.

Architecture:

- **``_run_logs``** -- module-level dict mapping ``run_id`` (str) to a list of
  log entry dicts. Each entry has ``ts``, ``level``, and ``msg`` keys.
  Capped at ``_MAX_ENTRIES_PER_RUN`` entries per run.

- **``emit_log``** -- append a structured log entry for a run. Called by the
  pipeline executor and dispatcher at key lifecycle moments.

- **``make_log_sink``** -- factory that returns a ``log_sink`` callable bound
  to a specific ``run_id``. Passed to the executor/dispatcher so they can
  emit log entries without knowing about the storage mechanism.

- **``get_run_log``** -- FastAPI endpoint returning log entries since a given
  offset, enabling incremental polling from the UI.

Design constraints:

- No ``hashlib`` / ``secrets`` imports (FIPS adapter policy per ADR-010).
- Pure in-memory storage -- no database dependency. Logs are ephemeral and
  exist only for the lifetime of the process. Sufficient for single-worker
  dev/lab deployments.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter

__all__ = [
    "clear_run_log",
    "emit_log",
    "get_run_log_entries",
    "make_log_sink",
    "router",
]

# === Storage ==================================================================

_MAX_ENTRIES_PER_RUN = 5000

# Module-level storage: run_id (str) -> list of log entry dicts.
# Thread-safe via _lock for the rare case of concurrent background tasks
# writing to the same run (shouldn't happen, but defensive).
_run_logs: dict[str, list[dict[str, Any]]] = {}
_lock = threading.Lock()


def emit_log(run_id: str, level: str, msg: str) -> None:
    """Append a structured log entry for a run.

    Args:
        run_id: The run UUID as a string.
        level: Log level -- ``"info"``, ``"warn"``, or ``"error"``.
        msg: Human-readable log message.
    """
    entry = {
        "ts": datetime.now(UTC).isoformat(),
        "level": level,
        "msg": msg,
    }
    with _lock:
        if run_id not in _run_logs:
            _run_logs[run_id] = []
        log_list = _run_logs[run_id]
        log_list.append(entry)
        # Cap at max entries -- drop oldest when exceeded
        if len(log_list) > _MAX_ENTRIES_PER_RUN:
            _run_logs[run_id] = log_list[-_MAX_ENTRIES_PER_RUN:]


def get_run_log_entries(
    run_id: str,
    since: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """Return log entries for a run since the given offset.

    Args:
        run_id: The run UUID as a string.
        since: Index offset -- only entries at index >= since are returned.

    Returns:
        Tuple of (entries_list, total_count).
    """
    with _lock:
        log_list = _run_logs.get(run_id, [])
        total = len(log_list)
        if since >= total:
            return [], total
        return list(log_list[since:]), total


def clear_run_log(run_id: str) -> None:
    """Remove all log entries for a run.

    Called during cleanup or when a run's logs are no longer needed.
    """
    with _lock:
        _run_logs.pop(run_id, None)


def make_log_sink(run_id: UUID | str) -> Any:
    """Create a log sink callable bound to a specific run_id.

    Returns a callable with signature ``(level: str, msg: str) -> None``
    that appends to the run's log accumulator. Suitable for passing as
    ``log_sink`` to ``RunExecutor`` and ``PipelineDispatcher``.

    Args:
        run_id: The run UUID (converted to string internally).

    Returns:
        A callable ``(level, msg) -> None``.
    """
    rid = str(run_id)

    def _sink(level: str, msg: str) -> None:
        emit_log(rid, level, msg)

    return _sink


# === FastAPI endpoint =========================================================

router = APIRouter(tags=["run-log"])


@router.get("/v1/tenants/{tenant_id}/runs/{run_id}/log")
async def get_run_log(
    tenant_id: UUID,
    run_id: UUID,
    since: int = 0,
) -> dict[str, Any]:
    """Return structured log entries for a pipeline run.

    Query parameters:
        since: Index offset. Only entries at index >= since are returned.
            The UI tracks the last ``total`` value and passes it as ``since``
            on the next poll to receive only new entries.

    Returns:
        ``{"entries": [...], "total": N}`` where each entry has
        ``ts``, ``level``, and ``msg`` keys.
    """
    entries, total = get_run_log_entries(str(run_id), since=since)
    return {"entries": entries, "total": total}
