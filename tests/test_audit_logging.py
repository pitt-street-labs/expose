"""Tests for NIST AU-2/AU-3 audit logging subsystem.

Coverage:

1. ``AuditEvent`` model validation — all fields accepted, types enforced.
2. ``AuditEventType`` — all 18 enum members are valid ``StrEnum`` values.
3. Audit log append-only — write, verify, write again, verify both records.
4. Serialization round-trip — model_dump → JSON → parse → reconstruct.
5. ``retention_category`` present on every event (default + explicit).
6. ``configure_audit_logging`` creates a functional logger.
7. ``emit_audit_event`` writes a parseable JSON line to the log.
8. Unconfigured logger silently drops events (no crash).
9. Optional fields accept ``None`` and non-``None`` values.
10. Invalid ``event_type`` rejected by Pydantic validation.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from expose.observability.audit_schema import AuditEvent, AuditEventType
from expose.observability.logging import (
    _AUDIT_LOGGER_NAME,
    configure_audit_logging,
    emit_audit_event,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(**overrides: object) -> AuditEvent:
    """Build a minimal valid AuditEvent, applying any overrides."""
    defaults: dict[str, object] = {
        "event_id": uuid4(),
        "event_type": AuditEventType.RUN_STARTED,
        "timestamp": datetime.now(tz=UTC),
        "actor": "test-user@example.com",
        "action": "Started recon run",
        "resource": "run/018f-abcd",
        "outcome": "success",
        "details": {"target": "example.com"},
    }
    defaults.update(overrides)
    return AuditEvent(**defaults)  # type: ignore[arg-type]


def _reset_audit_logger() -> None:
    """Close and remove all handlers from the audit logger to isolate tests."""
    logger = logging.getLogger(_AUDIT_LOGGER_NAME)
    for handler in list(logger.handlers):
        handler.close()
    logger.handlers.clear()
    logger.propagate = False


# ---------------------------------------------------------------------------
# AuditEventType enum tests
# ---------------------------------------------------------------------------


_EXPECTED_EVENT_TYPES = [
    ("RUN_STARTED", "run_started"),
    ("RUN_COMPLETED", "run_completed"),
    ("RUN_FAILED", "run_failed"),
    ("ENTITY_CREATED", "entity_created"),
    ("ENTITY_UPDATED", "entity_updated"),
    ("SCOPE_DENIAL", "scope_denial"),
    ("TENANT_CREATED", "tenant_created"),
    ("TENANT_DELETED", "tenant_deleted"),
    ("CREDENTIAL_ACCESSED", "credential_accessed"),
    ("CREDENTIAL_ROTATED", "credential_rotated"),
    ("DATA_EXPORT", "data_export"),
    ("DATA_DELETION", "data_deletion"),
    ("CONFIG_CHANGED", "config_changed"),
    ("AUTH_SUCCESS", "auth_success"),
    ("AUTH_FAILURE", "auth_failure"),
    ("ARTIFACT_SIGNED", "artifact_signed"),
    ("SCHEDULE_CREATED", "schedule_created"),
    ("SCHEDULE_DELETED", "schedule_deleted"),
]


class TestAuditEventType:
    """Verify the AU-2 auditable event catalog."""

    def test_all_members_are_strenum(self) -> None:
        """Every AuditEventType member is a valid StrEnum with a string value."""
        for member in AuditEventType:
            assert isinstance(member, str)
            assert isinstance(member.value, str)

    def test_member_count(self) -> None:
        """Exactly 18 event types in the AU-2 catalog."""
        assert len(AuditEventType) == 18

    @pytest.mark.parametrize(("name", "value"), _EXPECTED_EVENT_TYPES)
    def test_expected_member(self, name: str, value: str) -> None:
        """Each specified event type exists with the expected string value."""
        member = AuditEventType[name]
        assert member.value == value
        assert str(member) == value


# ---------------------------------------------------------------------------
# AuditEvent model validation tests
# ---------------------------------------------------------------------------


class TestAuditEventModel:
    """Verify AU-3 content fields and Pydantic validation."""

    def test_all_required_fields_accepted(self) -> None:
        """A fully-populated AuditEvent is valid."""
        event = _make_event()
        assert isinstance(event.event_id, UUID)
        assert isinstance(event.event_type, AuditEventType)
        assert isinstance(event.timestamp, datetime)
        assert isinstance(event.actor, str)
        assert isinstance(event.action, str)
        assert isinstance(event.resource, str)
        assert isinstance(event.outcome, str)
        assert isinstance(event.details, dict)

    def test_optional_fields_default_none(self) -> None:
        """Optional fields default to None when not provided."""
        event = _make_event()
        assert event.source_ip is None
        assert event.tenant_id is None
        assert event.run_id is None
        assert event.correlation_id is None

    def test_optional_fields_accept_values(self) -> None:
        """Optional fields accept non-None values."""
        tid = uuid4()
        rid = uuid4()
        event = _make_event(
            source_ip="10.0.0.1",
            tenant_id=tid,
            run_id=rid,
            correlation_id="corr-abc-123",
        )
        assert event.source_ip == "10.0.0.1"
        assert event.tenant_id == tid
        assert event.run_id == rid
        assert event.correlation_id == "corr-abc-123"

    def test_retention_category_default(self) -> None:
        """retention_category defaults to 'standard' per AU-11."""
        event = _make_event()
        assert event.retention_category == "standard"

    def test_retention_category_explicit(self) -> None:
        """retention_category accepts an explicit value."""
        event = _make_event(retention_category="extended")
        assert event.retention_category == "extended"

    def test_retention_category_present_all_event_types(self) -> None:
        """Every event type produces a record with retention_category set."""
        for evt_type in AuditEventType:
            event = _make_event(event_type=evt_type)
            assert hasattr(event, "retention_category")
            assert event.retention_category == "standard"

    def test_invalid_event_type_rejected(self) -> None:
        """An invalid event_type string is rejected by Pydantic."""
        with pytest.raises(Exception):  # noqa: B017 — ValidationError
            _make_event(event_type="not_a_real_event")

    def test_model_is_frozen(self) -> None:
        """AuditEvent instances are immutable (frozen=True)."""
        event = _make_event()
        with pytest.raises(Exception):  # noqa: B017 — ValidationError
            event.actor = "someone-else"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Serialization round-trip tests
# ---------------------------------------------------------------------------


class TestSerializationRoundTrip:
    """Verify audit records survive JSON serialization and deserialization."""

    def test_model_dump_json_mode(self) -> None:
        """model_dump(mode='json') produces a JSON-serializable dict."""
        event = _make_event(
            source_ip="192.168.1.1",
            tenant_id=uuid4(),
            run_id=uuid4(),
            correlation_id="trace-xyz",
            retention_category="extended",
        )
        dumped = event.model_dump(mode="json")
        # Must be JSON-serializable without error.
        json_str = json.dumps(dumped)
        assert isinstance(json_str, str)

    def test_round_trip_preserves_fields(self) -> None:
        """Serialize → deserialize produces an equivalent AuditEvent."""
        original = _make_event(
            source_ip="10.20.30.40",
            tenant_id=uuid4(),
            run_id=uuid4(),
            correlation_id="rt-test",
            retention_category="legal-hold",
        )
        json_str = json.dumps(original.model_dump(mode="json"))
        parsed = json.loads(json_str)
        restored = AuditEvent(**parsed)

        assert restored.event_id == original.event_id
        assert restored.event_type == original.event_type
        assert restored.actor == original.actor
        assert restored.action == original.action
        assert restored.resource == original.resource
        assert restored.outcome == original.outcome
        assert restored.details == original.details
        assert restored.source_ip == original.source_ip
        assert restored.tenant_id == original.tenant_id
        assert restored.run_id == original.run_id
        assert restored.correlation_id == original.correlation_id
        assert restored.retention_category == original.retention_category

    def test_json_line_is_single_line(self) -> None:
        """Serialized JSON has no embedded newlines (NDJSON requirement)."""
        event = _make_event(details={"note": "multi\nline\nvalue"})
        json_str = json.dumps(event.model_dump(mode="json"), separators=(",", ":"))
        assert "\n" not in json_str


# ---------------------------------------------------------------------------
# Audit logger configuration tests
# ---------------------------------------------------------------------------


class TestConfigureAuditLogging:
    """Verify the audit logger setup."""

    def setup_method(self) -> None:
        _reset_audit_logger()

    def teardown_method(self) -> None:
        _reset_audit_logger()

    def test_creates_logger(self, tmp_path: Path) -> None:
        """configure_audit_logging returns a functional Logger."""
        log_path = tmp_path / "audit.log"
        logger = configure_audit_logging(path=str(log_path))
        assert isinstance(logger, logging.Logger)
        assert logger.name == _AUDIT_LOGGER_NAME

    def test_logger_has_file_handler(self, tmp_path: Path) -> None:
        """The returned logger has exactly one FileHandler."""
        log_path = tmp_path / "audit.log"
        logger = configure_audit_logging(path=str(log_path))
        assert len(logger.handlers) == 1
        assert isinstance(logger.handlers[0], logging.FileHandler)

    def test_logger_does_not_propagate(self, tmp_path: Path) -> None:
        """Audit logger propagate=False to avoid duplicate output."""
        log_path = tmp_path / "audit.log"
        logger = configure_audit_logging(path=str(log_path))
        assert logger.propagate is False

    def test_reconfigure_clears_old_handlers(self, tmp_path: Path) -> None:
        """Calling configure_audit_logging twice does not duplicate handlers."""
        log1 = tmp_path / "audit1.log"
        log2 = tmp_path / "audit2.log"
        configure_audit_logging(path=str(log1))
        logger = configure_audit_logging(path=str(log2))
        assert len(logger.handlers) == 1

    def test_env_var_fallback(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """When path is None, EXPOSE_AUDIT_LOG_PATH env var is used."""
        log_path = tmp_path / "env-audit.log"
        monkeypatch.setenv("EXPOSE_AUDIT_LOG_PATH", str(log_path))
        logger = configure_audit_logging()
        assert len(logger.handlers) == 1
        handler = logger.handlers[0]
        assert isinstance(handler, logging.FileHandler)
        assert handler.baseFilename == str(log_path)


# ---------------------------------------------------------------------------
# Audit log append-only and emit tests
# ---------------------------------------------------------------------------


class TestEmitAuditEvent:
    """Verify audit events are written as append-only NDJSON."""

    def setup_method(self) -> None:
        _reset_audit_logger()

    def teardown_method(self) -> None:
        _reset_audit_logger()

    def test_emit_writes_json_line(self, tmp_path: Path) -> None:
        """emit_audit_event writes a valid JSON line to the audit log."""
        log_path = tmp_path / "audit.log"
        configure_audit_logging(path=str(log_path))

        event = _make_event()
        emit_audit_event(event)

        # Force flush.
        logger = logging.getLogger(_AUDIT_LOGGER_NAME)
        for h in logger.handlers:
            h.flush()

        lines = log_path.read_text().strip().splitlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["event_type"] == "run_started"
        assert record["actor"] == "test-user@example.com"

    def test_append_only_multiple_events(self, tmp_path: Path) -> None:
        """Two emits produce two lines — second does not overwrite first."""
        log_path = tmp_path / "audit.log"
        configure_audit_logging(path=str(log_path))

        event1 = _make_event(action="First action")
        event2 = _make_event(
            event_type=AuditEventType.RUN_COMPLETED,
            action="Second action",
        )
        emit_audit_event(event1)
        emit_audit_event(event2)

        logger = logging.getLogger(_AUDIT_LOGGER_NAME)
        for h in logger.handlers:
            h.flush()

        lines = log_path.read_text().strip().splitlines()
        assert len(lines) == 2

        r1 = json.loads(lines[0])
        r2 = json.loads(lines[1])
        assert r1["action"] == "First action"
        assert r2["action"] == "Second action"
        assert r2["event_type"] == "run_completed"

    def test_each_line_is_valid_json(self, tmp_path: Path) -> None:
        """Every line in the audit log parses as valid JSON independently."""
        log_path = tmp_path / "audit.log"
        configure_audit_logging(path=str(log_path))

        for evt_type in list(AuditEventType)[:5]:
            emit_audit_event(_make_event(event_type=evt_type))

        logger = logging.getLogger(_AUDIT_LOGGER_NAME)
        for h in logger.handlers:
            h.flush()

        lines = log_path.read_text().strip().splitlines()
        assert len(lines) == 5
        for line in lines:
            parsed = json.loads(line)
            assert "event_id" in parsed
            assert "timestamp" in parsed

    def test_unconfigured_logger_drops_silently(self) -> None:
        """emit_audit_event does not crash when logger has no handlers."""
        _reset_audit_logger()
        event = _make_event()
        # Must not raise.
        emit_audit_event(event)

    def test_retention_category_in_serialized_output(self, tmp_path: Path) -> None:
        """retention_category appears in the JSON log line."""
        log_path = tmp_path / "audit.log"
        configure_audit_logging(path=str(log_path))

        emit_audit_event(_make_event(retention_category="legal-hold"))

        logger = logging.getLogger(_AUDIT_LOGGER_NAME)
        for h in logger.handlers:
            h.flush()

        record = json.loads(log_path.read_text().strip())
        assert record["retention_category"] == "legal-hold"

    def test_all_au3_fields_in_output(self, tmp_path: Path) -> None:
        """Every AU-3 required field is present in the serialized record."""
        log_path = tmp_path / "audit.log"
        configure_audit_logging(path=str(log_path))

        event = _make_event(
            source_ip="10.0.0.1",
            tenant_id=uuid4(),
            run_id=uuid4(),
            correlation_id="au3-check",
        )
        emit_audit_event(event)

        logger = logging.getLogger(_AUDIT_LOGGER_NAME)
        for h in logger.handlers:
            h.flush()

        record = json.loads(log_path.read_text().strip())
        required_keys = {
            "event_id", "event_type", "timestamp", "actor", "action",
            "resource", "outcome", "details", "source_ip", "tenant_id",
            "run_id", "correlation_id", "retention_category",
        }
        assert required_keys.issubset(record.keys())
