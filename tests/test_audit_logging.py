"""Tests for NIST AU-2/AU-3 audit logging subsystem.

Coverage:

1. ``AuditEvent`` model validation — all fields accepted, types enforced.
2. ``AuditEventType`` — all 33 enum members are valid ``StrEnum`` values.
3. Audit log append-only — write, verify, write again, verify both records.
4. Serialization round-trip — model_dump → JSON → parse → reconstruct.
5. ``retention_category`` present on every event (default + explicit).
6. ``configure_audit_logging`` creates a functional logger.
7. ``emit_audit_event`` writes a parseable JSON line to the log.
8. Unconfigured logger silently drops events (no crash).
9. Optional fields accept ``None`` and non-``None`` values.
10. Invalid ``event_type`` rejected by Pydantic validation.
11. ``sanitize_details`` redacts sensitive keys (passwords, secrets, tokens,
    api_keys, credentials) including nested dicts.
12. ``emit_audit_event`` applies ``sanitize_details`` before writing.
13. ``AuditLogger`` convenience methods — each event category produces correct
    event_type, action, outcome, and AU-3 fields.
14. ``AuditRetentionConfig`` — configurable retention periods, defaults, and
    fallback behavior.
15. New AU-2 event types — token lifecycle, tier-3 gate, tenant isolation,
    entity queries, artifact downloads, collector dispatch, enrichment,
    credential CRUD.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from expose.observability.audit_schema import (
    AuditEvent,
    AuditEventType,
    AuditLogger,
    AuditRetentionConfig,
    DEFAULT_RETENTION_DAYS,
    sanitize_details,
)
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


def _flush_audit_logger() -> None:
    """Flush all handlers on the audit logger."""
    logger = logging.getLogger(_AUDIT_LOGGER_NAME)
    for h in logger.handlers:
        h.flush()


# ---------------------------------------------------------------------------
# AuditEventType enum tests
# ---------------------------------------------------------------------------

# Complete catalog of all 32 AU-2 event types (9 new in issue #107).
_EXPECTED_EVENT_TYPES = [
    # Run lifecycle
    ("RUN_STARTED", "run_started"),
    ("RUN_COMPLETED", "run_completed"),
    ("RUN_FAILED", "run_failed"),
    # Entity lifecycle
    ("ENTITY_CREATED", "entity_created"),
    ("ENTITY_UPDATED", "entity_updated"),
    # Data access (new)
    ("ENTITY_QUERIED", "entity_queried"),
    ("ARTIFACT_DOWNLOADED", "artifact_downloaded"),
    # Scope enforcement
    ("SCOPE_DENIAL", "scope_denial"),
    # Tenant lifecycle
    ("TENANT_CREATED", "tenant_created"),
    ("TENANT_DELETED", "tenant_deleted"),
    # Credential operations (expanded)
    ("CREDENTIAL_CREATED", "credential_created"),
    ("CREDENTIAL_ACCESSED", "credential_accessed"),
    ("CREDENTIAL_ROTATED", "credential_rotated"),
    ("CREDENTIAL_DELETED", "credential_deleted"),
    # Data lifecycle
    ("DATA_EXPORT", "data_export"),
    ("DATA_DELETION", "data_deletion"),
    # Configuration
    ("CONFIG_CHANGED", "config_changed"),
    # Authentication (expanded)
    ("AUTH_SUCCESS", "auth_success"),
    ("AUTH_FAILURE", "auth_failure"),
    ("TOKEN_CREATED", "token_created"),
    ("TOKEN_VALIDATION_FAILED", "token_validation_failed"),
    # Authorization (expanded)
    ("AUTHORIZATION_DENIED", "authorization_denied"),
    ("TIER3_GATE_DENIED", "tier3_gate_denied"),
    ("TENANT_ISOLATION_VIOLATION", "tenant_isolation_violation"),
    # Artifact signing
    ("ARTIFACT_SIGNED", "artifact_signed"),
    ("SIGNATURE_VERIFICATION_FAILED", "signature_verification_failed"),
    # Scheduling
    ("SCHEDULE_CREATED", "schedule_created"),
    ("SCHEDULE_DELETED", "schedule_deleted"),
    ("SCHEDULE_UPDATED", "schedule_updated"),
    # Pipeline operations (new)
    ("COLLECTOR_DISPATCHED", "collector_dispatched"),
    ("ENRICHMENT_COMPLETED", "enrichment_completed"),
    # SIEM delivery
    ("SIEM_DELIVERY_FAILED", "siem_delivery_failed"),
    # Credential resolution
    ("CREDENTIAL_RESOLUTION_FAILED", "credential_resolution_failed"),
]


class TestAuditEventType:
    """Verify the AU-2 auditable event catalog."""

    def test_all_members_are_strenum(self) -> None:
        """Every AuditEventType member is a valid StrEnum with a string value."""
        for member in AuditEventType:
            assert isinstance(member, str)
            assert isinstance(member.value, str)

    def test_member_count(self) -> None:
        """Exactly 33 event types in the extended AU-2 catalog."""
        assert len(AuditEventType) == 33

    @pytest.mark.parametrize(("name", "value"), _EXPECTED_EVENT_TYPES)
    def test_expected_member(self, name: str, value: str) -> None:
        """Each specified event type exists with the expected string value."""
        member = AuditEventType[name]
        assert member.value == value
        assert str(member) == value

    def test_new_auth_event_types(self) -> None:
        """New authentication event types exist."""
        assert AuditEventType.TOKEN_CREATED == "token_created"
        assert AuditEventType.TOKEN_VALIDATION_FAILED == "token_validation_failed"

    def test_new_authz_event_types(self) -> None:
        """New authorization event types exist."""
        assert AuditEventType.TIER3_GATE_DENIED == "tier3_gate_denied"
        assert AuditEventType.TENANT_ISOLATION_VIOLATION == "tenant_isolation_violation"

    def test_new_data_access_event_types(self) -> None:
        """New data access event types exist."""
        assert AuditEventType.ENTITY_QUERIED == "entity_queried"
        assert AuditEventType.ARTIFACT_DOWNLOADED == "artifact_downloaded"

    def test_new_pipeline_event_types(self) -> None:
        """New pipeline event types exist."""
        assert AuditEventType.COLLECTOR_DISPATCHED == "collector_dispatched"
        assert AuditEventType.ENRICHMENT_COMPLETED == "enrichment_completed"

    def test_new_credential_event_types(self) -> None:
        """New credential CRUD event types exist."""
        assert AuditEventType.CREDENTIAL_CREATED == "credential_created"
        assert AuditEventType.CREDENTIAL_DELETED == "credential_deleted"


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
        """Serialize -> deserialize produces an equivalent AuditEvent."""
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
        _flush_audit_logger()

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
        _flush_audit_logger()

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
        _flush_audit_logger()

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
        _flush_audit_logger()

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
        _flush_audit_logger()

        record = json.loads(log_path.read_text().strip())
        required_keys = {
            "event_id", "event_type", "timestamp", "actor", "action",
            "resource", "outcome", "details", "source_ip", "tenant_id",
            "run_id", "correlation_id", "retention_category",
        }
        assert required_keys.issubset(record.keys())


# ---------------------------------------------------------------------------
# sanitize_details tests (issue #150)
# ---------------------------------------------------------------------------


class TestSanitizeDetails:
    """Verify sensitive key patterns are redacted from details dicts."""

    def test_password_key_redacted(self) -> None:
        """Keys containing 'password' are redacted."""
        result = sanitize_details({"db_password": "s3cret", "host": "db.local"})
        assert result["db_password"] == "[REDACTED]"
        assert result["host"] == "db.local"

    def test_secret_key_redacted(self) -> None:
        """Keys containing 'secret' are redacted."""
        result = sanitize_details({"client_secret": "abc123"})
        assert result["client_secret"] == "[REDACTED]"

    def test_token_key_redacted(self) -> None:
        """Keys containing 'token' are redacted."""
        result = sanitize_details({"auth_token": "tok_xyz", "scope": "read"})
        assert result["auth_token"] == "[REDACTED]"
        assert result["scope"] == "read"

    def test_api_key_redacted(self) -> None:
        """Keys containing 'api_key' are redacted."""
        result = sanitize_details({"shodan_api_key": "ABCDEF"})
        assert result["shodan_api_key"] == "[REDACTED]"

    def test_credential_key_redacted(self) -> None:
        """Keys containing 'credential' are redacted."""
        result = sanitize_details({"credential_data": "vault:xyz"})
        assert result["credential_data"] == "[REDACTED]"

    def test_case_insensitive(self) -> None:
        """Matching is case-insensitive."""
        result = sanitize_details({
            "API_KEY": "k1",
            "Password": "p1",
            "SECRET_VALUE": "s1",
        })
        assert result["API_KEY"] == "[REDACTED]"
        assert result["Password"] == "[REDACTED]"
        assert result["SECRET_VALUE"] == "[REDACTED]"

    def test_non_sensitive_keys_preserved(self) -> None:
        """Keys that don't match sensitive patterns are left unchanged."""
        details = {"domain": "example.com", "count": 42, "status": "ok"}
        result = sanitize_details(details)
        assert result == details

    def test_nested_dict_sanitized(self) -> None:
        """Nested dicts are sanitized recursively."""
        result = sanitize_details({
            "config": {
                "api_key": "nested-key",
                "endpoint": "https://api.example.com",
            },
            "name": "test",
        })
        assert result["config"]["api_key"] == "[REDACTED]"
        assert result["config"]["endpoint"] == "https://api.example.com"
        assert result["name"] == "test"

    def test_deeply_nested_sanitization(self) -> None:
        """Sanitization works at arbitrary nesting depth."""
        result = sanitize_details({
            "level1": {
                "level2": {
                    "secret_key": "deep-secret",
                    "value": "ok",
                },
            },
        })
        assert result["level1"]["level2"]["secret_key"] == "[REDACTED]"
        assert result["level1"]["level2"]["value"] == "ok"

    def test_empty_dict(self) -> None:
        """Empty dict returns empty dict."""
        assert sanitize_details({}) == {}

    def test_original_not_mutated(self) -> None:
        """The original dict is never mutated."""
        original = {"password": "secret123", "host": "db.local"}
        _ = sanitize_details(original)
        assert original["password"] == "secret123"

    def test_multiple_sensitive_keys(self) -> None:
        """Multiple sensitive keys in the same dict are all redacted."""
        result = sanitize_details({
            "db_password": "p1",
            "api_token": "t1",
            "client_secret": "s1",
            "shodan_api_key": "k1",
            "ssh_credential": "c1",
            "host": "safe-value",
        })
        assert result["db_password"] == "[REDACTED]"
        assert result["api_token"] == "[REDACTED]"
        assert result["client_secret"] == "[REDACTED]"
        assert result["shodan_api_key"] == "[REDACTED]"
        assert result["ssh_credential"] == "[REDACTED]"
        assert result["host"] == "safe-value"


class TestEmitSanitizesDetails:
    """Verify emit_audit_event applies sanitize_details before writing."""

    def setup_method(self) -> None:
        _reset_audit_logger()

    def teardown_method(self) -> None:
        _reset_audit_logger()

    def test_emit_redacts_password_in_details(self, tmp_path: Path) -> None:
        """Passwords in the details dict are redacted in the log output."""
        log_path = tmp_path / "audit.log"
        configure_audit_logging(path=str(log_path))

        event = _make_event(details={"db_password": "supersecret", "host": "db.local"})
        emit_audit_event(event)
        _flush_audit_logger()

        record = json.loads(log_path.read_text().strip())
        assert record["details"]["db_password"] == "[REDACTED]"
        assert record["details"]["host"] == "db.local"

    def test_emit_redacts_nested_sensitive_keys(self, tmp_path: Path) -> None:
        """Nested sensitive keys are redacted in the log output."""
        log_path = tmp_path / "audit.log"
        configure_audit_logging(path=str(log_path))

        event = _make_event(details={
            "collector_config": {
                "api_key": "SHODAN_KEY_123",
                "endpoint": "https://api.shodan.io",
            },
        })
        emit_audit_event(event)
        _flush_audit_logger()

        record = json.loads(log_path.read_text().strip())
        assert record["details"]["collector_config"]["api_key"] == "[REDACTED]"
        assert record["details"]["collector_config"]["endpoint"] == "https://api.shodan.io"

    def test_emit_preserves_non_sensitive_details(self, tmp_path: Path) -> None:
        """Non-sensitive details pass through unchanged."""
        log_path = tmp_path / "audit.log"
        configure_audit_logging(path=str(log_path))

        event = _make_event(details={"domain": "example.com", "count": 5})
        emit_audit_event(event)
        _flush_audit_logger()

        record = json.loads(log_path.read_text().strip())
        assert record["details"]["domain"] == "example.com"
        assert record["details"]["count"] == 5


# ---------------------------------------------------------------------------
# AuditRetentionConfig tests
# ---------------------------------------------------------------------------


class TestAuditRetentionConfig:
    """Verify configurable retention periods per AU-11."""

    def test_default_values(self) -> None:
        """Default retention config matches the 90/365/-1 standard."""
        config = AuditRetentionConfig()
        assert config.standard_days == 90
        assert config.extended_days == 365
        assert config.legal_hold_days == -1

    def test_custom_values(self) -> None:
        """Custom retention periods are accepted."""
        config = AuditRetentionConfig(
            standard_days=180,
            extended_days=730,
            legal_hold_days=-1,
        )
        assert config.standard_days == 180
        assert config.extended_days == 730

    def test_days_for_standard(self) -> None:
        """days_for('standard') returns standard_days."""
        config = AuditRetentionConfig(standard_days=120)
        assert config.days_for("standard") == 120

    def test_days_for_extended(self) -> None:
        """days_for('extended') returns extended_days."""
        config = AuditRetentionConfig(extended_days=500)
        assert config.days_for("extended") == 500

    def test_days_for_legal_hold(self) -> None:
        """days_for('legal-hold') returns legal_hold_days."""
        config = AuditRetentionConfig(legal_hold_days=-1)
        assert config.days_for("legal-hold") == -1

    def test_days_for_unknown_falls_back_to_standard(self) -> None:
        """Unknown retention category falls back to standard_days."""
        config = AuditRetentionConfig(standard_days=90)
        assert config.days_for("unknown-category") == 90

    def test_config_is_frozen(self) -> None:
        """AuditRetentionConfig is immutable."""
        config = AuditRetentionConfig()
        with pytest.raises(Exception):  # noqa: B017 — ValidationError
            config.standard_days = 999  # type: ignore[misc]

    def test_default_retention_days_constant(self) -> None:
        """DEFAULT_RETENTION_DAYS module constant has the expected keys."""
        assert DEFAULT_RETENTION_DAYS["standard"] == 90
        assert DEFAULT_RETENTION_DAYS["extended"] == 365
        assert DEFAULT_RETENTION_DAYS["legal-hold"] == -1


# ---------------------------------------------------------------------------
# AuditLogger class tests
# ---------------------------------------------------------------------------


class TestAuditLogger:
    """Verify the AuditLogger convenience class for each AU-2 event category."""

    def setup_method(self) -> None:
        _reset_audit_logger()

    def teardown_method(self) -> None:
        _reset_audit_logger()

    def _make_logger(self, tmp_path: Path) -> tuple[AuditLogger, Path]:
        """Create an AuditLogger with a file-backed audit log."""
        log_path = tmp_path / "audit.log"
        configure_audit_logging(path=str(log_path))
        return AuditLogger(), log_path

    def _read_last_record(self, log_path: Path) -> dict:
        """Read and parse the last JSON line from the audit log."""
        _flush_audit_logger()
        lines = log_path.read_text().strip().splitlines()
        return json.loads(lines[-1])

    # -- Retention config access --

    def test_default_retention_config(self) -> None:
        """AuditLogger uses default retention when none specified."""
        audit = AuditLogger()
        assert audit.retention.standard_days == 90

    def test_custom_retention_config(self) -> None:
        """AuditLogger accepts a custom retention config."""
        config = AuditRetentionConfig(standard_days=180)
        audit = AuditLogger(retention=config)
        assert audit.retention.standard_days == 180

    # -- Authentication events --

    def test_log_auth_success(self, tmp_path: Path) -> None:
        """log_auth_success produces correct event_type and outcome."""
        audit, log_path = self._make_logger(tmp_path)
        event = audit.log_auth_success(
            actor="admin@example.com",
            source_ip="10.0.0.1",
        )
        assert event.event_type == AuditEventType.AUTH_SUCCESS
        assert event.outcome == "success"
        assert event.source_ip == "10.0.0.1"

        record = self._read_last_record(log_path)
        assert record["event_type"] == "auth_success"
        assert record["outcome"] == "success"

    def test_log_auth_failure(self, tmp_path: Path) -> None:
        """log_auth_failure produces correct event_type and outcome."""
        audit, log_path = self._make_logger(tmp_path)
        event = audit.log_auth_failure(
            actor="unknown@example.com",
            source_ip="10.0.0.99",
            details={"reason": "invalid_password"},
        )
        assert event.event_type == AuditEventType.AUTH_FAILURE
        assert event.outcome == "failure"

        record = self._read_last_record(log_path)
        assert record["event_type"] == "auth_failure"
        assert record["details"]["reason"] == "invalid_password"

    def test_log_token_created(self, tmp_path: Path) -> None:
        """log_token_created produces correct event_type."""
        audit, log_path = self._make_logger(tmp_path)
        event = audit.log_token_created(actor="admin@example.com")
        assert event.event_type == AuditEventType.TOKEN_CREATED
        assert event.outcome == "success"

        record = self._read_last_record(log_path)
        assert record["event_type"] == "token_created"

    def test_log_token_validation_failed(self, tmp_path: Path) -> None:
        """log_token_validation_failed produces correct event_type."""
        audit, log_path = self._make_logger(tmp_path)
        event = audit.log_token_validation_failed(
            actor="system",
            details={"token_prefix": "exp_"},
        )
        assert event.event_type == AuditEventType.TOKEN_VALIDATION_FAILED
        assert event.outcome == "failure"

        record = self._read_last_record(log_path)
        assert record["event_type"] == "token_validation_failed"

    # -- Authorization events --

    def test_log_scope_denial(self, tmp_path: Path) -> None:
        """log_scope_denial produces correct event_type and outcome."""
        audit, log_path = self._make_logger(tmp_path)
        event = audit.log_scope_denial(
            actor="user@example.com",
            resource="entity/outside-scope",
        )
        assert event.event_type == AuditEventType.SCOPE_DENIAL
        assert event.outcome == "failure"

        record = self._read_last_record(log_path)
        assert record["event_type"] == "scope_denial"

    def test_log_authorization_denied(self, tmp_path: Path) -> None:
        """log_authorization_denied produces correct event_type."""
        audit, log_path = self._make_logger(tmp_path)
        event = audit.log_authorization_denied(
            actor="user@example.com",
            resource="admin/users",
        )
        assert event.event_type == AuditEventType.AUTHORIZATION_DENIED
        assert event.outcome == "failure"

        record = self._read_last_record(log_path)
        assert record["event_type"] == "authorization_denied"

    def test_log_tier3_gate_denied(self, tmp_path: Path) -> None:
        """log_tier3_gate_denied produces correct event_type."""
        audit, log_path = self._make_logger(tmp_path)
        event = audit.log_tier3_gate_denied(
            actor="free-tier@example.com",
            resource="modules/threat_context",
        )
        assert event.event_type == AuditEventType.TIER3_GATE_DENIED
        assert event.outcome == "failure"

        record = self._read_last_record(log_path)
        assert record["event_type"] == "tier3_gate_denied"

    def test_log_tenant_isolation_violation(self, tmp_path: Path) -> None:
        """log_tenant_isolation_violation produces correct event_type and extended retention."""
        audit, log_path = self._make_logger(tmp_path)
        tid = uuid4()
        event = audit.log_tenant_isolation_violation(
            actor="user@tenant-a.com",
            resource="tenant/tenant-b/entities",
            tenant_id=tid,
        )
        assert event.event_type == AuditEventType.TENANT_ISOLATION_VIOLATION
        assert event.outcome == "failure"
        # Isolation violations get extended retention.
        assert event.retention_category == "extended"

        record = self._read_last_record(log_path)
        assert record["event_type"] == "tenant_isolation_violation"
        assert record["retention_category"] == "extended"

    # -- Data access events --

    def test_log_entity_queried(self, tmp_path: Path) -> None:
        """log_entity_queried produces correct event_type."""
        audit, log_path = self._make_logger(tmp_path)
        event = audit.log_entity_queried(
            actor="analyst@example.com",
            resource="entity/example.com",
        )
        assert event.event_type == AuditEventType.ENTITY_QUERIED
        assert event.outcome == "success"

        record = self._read_last_record(log_path)
        assert record["event_type"] == "entity_queried"

    def test_log_artifact_downloaded(self, tmp_path: Path) -> None:
        """log_artifact_downloaded produces correct event_type."""
        audit, log_path = self._make_logger(tmp_path)
        event = audit.log_artifact_downloaded(
            actor="analyst@example.com",
            resource="artifact/screenshot-12345.png",
        )
        assert event.event_type == AuditEventType.ARTIFACT_DOWNLOADED
        assert event.outcome == "success"

        record = self._read_last_record(log_path)
        assert record["event_type"] == "artifact_downloaded"

    # -- Configuration events --

    def test_log_config_changed(self, tmp_path: Path) -> None:
        """log_config_changed produces correct event_type."""
        audit, log_path = self._make_logger(tmp_path)
        tid = uuid4()
        event = audit.log_config_changed(
            actor="admin@example.com",
            resource=f"tenant/{tid}/config",
            tenant_id=tid,
            details={"field": "llm_enabled", "old": False, "new": True},
        )
        assert event.event_type == AuditEventType.CONFIG_CHANGED
        assert event.outcome == "success"

        record = self._read_last_record(log_path)
        assert record["event_type"] == "config_changed"
        assert record["details"]["field"] == "llm_enabled"

    def test_log_schedule_created(self, tmp_path: Path) -> None:
        """log_schedule_created produces correct event_type."""
        audit, log_path = self._make_logger(tmp_path)
        event = audit.log_schedule_created(
            actor="admin@example.com",
            resource="schedule/daily-scan",
        )
        assert event.event_type == AuditEventType.SCHEDULE_CREATED

        record = self._read_last_record(log_path)
        assert record["event_type"] == "schedule_created"

    def test_log_schedule_updated(self, tmp_path: Path) -> None:
        """log_schedule_updated produces correct event_type."""
        audit, log_path = self._make_logger(tmp_path)
        event = audit.log_schedule_updated(
            actor="admin@example.com",
            resource="schedule/daily-scan",
        )
        assert event.event_type == AuditEventType.SCHEDULE_UPDATED

        record = self._read_last_record(log_path)
        assert record["event_type"] == "schedule_updated"

    def test_log_schedule_deleted(self, tmp_path: Path) -> None:
        """log_schedule_deleted produces correct event_type."""
        audit, log_path = self._make_logger(tmp_path)
        event = audit.log_schedule_deleted(
            actor="admin@example.com",
            resource="schedule/daily-scan",
        )
        assert event.event_type == AuditEventType.SCHEDULE_DELETED

        record = self._read_last_record(log_path)
        assert record["event_type"] == "schedule_deleted"

    def test_log_credential_created(self, tmp_path: Path) -> None:
        """log_credential_created produces correct event_type."""
        audit, log_path = self._make_logger(tmp_path)
        event = audit.log_credential_created(
            actor="admin@example.com",
            resource="credential/shodan",
        )
        assert event.event_type == AuditEventType.CREDENTIAL_CREATED

        record = self._read_last_record(log_path)
        assert record["event_type"] == "credential_created"

    def test_log_credential_rotated(self, tmp_path: Path) -> None:
        """log_credential_rotated produces correct event_type."""
        audit, log_path = self._make_logger(tmp_path)
        event = audit.log_credential_rotated(
            actor="admin@example.com",
            resource="credential/shodan",
        )
        assert event.event_type == AuditEventType.CREDENTIAL_ROTATED

        record = self._read_last_record(log_path)
        assert record["event_type"] == "credential_rotated"

    def test_log_credential_deleted(self, tmp_path: Path) -> None:
        """log_credential_deleted produces correct event_type."""
        audit, log_path = self._make_logger(tmp_path)
        event = audit.log_credential_deleted(
            actor="admin@example.com",
            resource="credential/shodan",
        )
        assert event.event_type == AuditEventType.CREDENTIAL_DELETED

        record = self._read_last_record(log_path)
        assert record["event_type"] == "credential_deleted"

    # -- Pipeline events --

    def test_log_run_started(self, tmp_path: Path) -> None:
        """log_run_started produces correct event_type."""
        audit, log_path = self._make_logger(tmp_path)
        rid = uuid4()
        event = audit.log_run_started(
            actor="system",
            resource=f"run/{rid}",
            run_id=rid,
            details={"target": "example.com"},
        )
        assert event.event_type == AuditEventType.RUN_STARTED
        assert event.outcome == "success"
        assert event.run_id == rid

        record = self._read_last_record(log_path)
        assert record["event_type"] == "run_started"

    def test_log_run_completed(self, tmp_path: Path) -> None:
        """log_run_completed produces correct event_type."""
        audit, log_path = self._make_logger(tmp_path)
        rid = uuid4()
        event = audit.log_run_completed(
            actor="system",
            resource=f"run/{rid}",
            run_id=rid,
        )
        assert event.event_type == AuditEventType.RUN_COMPLETED
        assert event.outcome == "success"

        record = self._read_last_record(log_path)
        assert record["event_type"] == "run_completed"

    def test_log_run_failed(self, tmp_path: Path) -> None:
        """log_run_failed produces correct event_type and failure outcome."""
        audit, log_path = self._make_logger(tmp_path)
        rid = uuid4()
        event = audit.log_run_failed(
            actor="system",
            resource=f"run/{rid}",
            run_id=rid,
            details={"error": "collector_timeout"},
        )
        assert event.event_type == AuditEventType.RUN_FAILED
        assert event.outcome == "failure"

        record = self._read_last_record(log_path)
        assert record["event_type"] == "run_failed"
        assert record["outcome"] == "failure"

    def test_log_collector_dispatched(self, tmp_path: Path) -> None:
        """log_collector_dispatched produces correct event_type."""
        audit, log_path = self._make_logger(tmp_path)
        rid = uuid4()
        event = audit.log_collector_dispatched(
            actor="system",
            resource="collector/ct_crtsh",
            run_id=rid,
            details={"domain": "example.com"},
        )
        assert event.event_type == AuditEventType.COLLECTOR_DISPATCHED
        assert event.outcome == "success"

        record = self._read_last_record(log_path)
        assert record["event_type"] == "collector_dispatched"

    def test_log_enrichment_completed(self, tmp_path: Path) -> None:
        """log_enrichment_completed produces correct event_type."""
        audit, log_path = self._make_logger(tmp_path)
        rid = uuid4()
        event = audit.log_enrichment_completed(
            actor="system",
            resource="enrichment/whois",
            run_id=rid,
        )
        assert event.event_type == AuditEventType.ENRICHMENT_COMPLETED
        assert event.outcome == "success"

        record = self._read_last_record(log_path)
        assert record["event_type"] == "enrichment_completed"


# ---------------------------------------------------------------------------
# AuditLogger — cross-cutting concerns
# ---------------------------------------------------------------------------


class TestAuditLoggerCrossCutting:
    """Verify AuditLogger behavior across all event methods."""

    def setup_method(self) -> None:
        _reset_audit_logger()

    def teardown_method(self) -> None:
        _reset_audit_logger()

    def test_every_event_has_uuid_event_id(self, tmp_path: Path) -> None:
        """Every emitted event gets a unique UUID event_id."""
        log_path = tmp_path / "audit.log"
        configure_audit_logging(path=str(log_path))
        audit = AuditLogger()

        e1 = audit.log_auth_success(actor="a@b.com")
        e2 = audit.log_auth_failure(actor="c@d.com")
        assert e1.event_id != e2.event_id
        assert isinstance(e1.event_id, UUID)

    def test_every_event_has_utc_timestamp(self, tmp_path: Path) -> None:
        """Every emitted event has a timezone-aware UTC timestamp."""
        log_path = tmp_path / "audit.log"
        configure_audit_logging(path=str(log_path))
        audit = AuditLogger()

        event = audit.log_auth_success(actor="a@b.com")
        assert event.timestamp.tzinfo is not None

    def test_tenant_id_propagated(self, tmp_path: Path) -> None:
        """tenant_id is propagated into the emitted event."""
        log_path = tmp_path / "audit.log"
        configure_audit_logging(path=str(log_path))
        audit = AuditLogger()
        tid = uuid4()

        event = audit.log_config_changed(
            actor="admin@example.com",
            resource="tenant/config",
            tenant_id=tid,
        )
        assert event.tenant_id == tid

    def test_source_ip_propagated(self, tmp_path: Path) -> None:
        """source_ip is propagated into the emitted event."""
        log_path = tmp_path / "audit.log"
        configure_audit_logging(path=str(log_path))
        audit = AuditLogger()

        event = audit.log_auth_success(
            actor="a@b.com",
            source_ip="192.168.1.100",
        )
        assert event.source_ip == "192.168.1.100"

    def test_details_sanitized_in_output(self, tmp_path: Path) -> None:
        """Sensitive keys in details are sanitized when written to log."""
        log_path = tmp_path / "audit.log"
        configure_audit_logging(path=str(log_path))
        audit = AuditLogger()

        audit.log_credential_created(
            actor="admin@example.com",
            resource="credential/shodan",
            details={"api_key": "SHODAN_KEY_123", "name": "shodan"},
        )
        _flush_audit_logger()

        record = json.loads(log_path.read_text().strip())
        assert record["details"]["api_key"] == "[REDACTED]"
        assert record["details"]["name"] == "shodan"

    def test_returns_audit_event(self, tmp_path: Path) -> None:
        """Every AuditLogger method returns the emitted AuditEvent."""
        log_path = tmp_path / "audit.log"
        configure_audit_logging(path=str(log_path))
        audit = AuditLogger()

        result = audit.log_run_started(
            actor="system",
            resource="run/test",
        )
        assert isinstance(result, AuditEvent)
        assert result.event_type == AuditEventType.RUN_STARTED

    def test_unconfigured_logger_does_not_crash(self) -> None:
        """AuditLogger methods do not crash when logger has no handlers."""
        _reset_audit_logger()
        audit = AuditLogger()
        # Must not raise.
        event = audit.log_auth_success(actor="test@example.com")
        assert isinstance(event, AuditEvent)

    def test_all_au3_fields_in_emitted_event(self, tmp_path: Path) -> None:
        """Every AU-3 field is present in events emitted through AuditLogger."""
        log_path = tmp_path / "audit.log"
        configure_audit_logging(path=str(log_path))
        audit = AuditLogger()
        tid = uuid4()
        rid = uuid4()

        event = audit.log_run_started(
            actor="system",
            resource=f"run/{rid}",
            run_id=rid,
            tenant_id=tid,
            source_ip="10.0.0.1",
            details={"target": "example.com"},
        )
        _flush_audit_logger()

        record = json.loads(log_path.read_text().strip())
        required_keys = {
            "event_id", "event_type", "timestamp", "actor", "action",
            "resource", "outcome", "details", "source_ip", "tenant_id",
            "run_id", "retention_category",
        }
        assert required_keys.issubset(record.keys())
        assert record["actor"] == "system"
        assert record["outcome"] == "success"
        assert record["details"]["target"] == "example.com"

    def test_iso8601_timestamp_format_in_output(self, tmp_path: Path) -> None:
        """Timestamp in the serialized output is ISO 8601."""
        log_path = tmp_path / "audit.log"
        configure_audit_logging(path=str(log_path))
        audit = AuditLogger()

        audit.log_auth_success(actor="a@b.com")
        _flush_audit_logger()

        record = json.loads(log_path.read_text().strip())
        ts = record["timestamp"]
        # ISO 8601: contains 'T' separator and timezone info.
        assert "T" in ts
        # Must be parseable as a datetime.
        parsed = datetime.fromisoformat(ts)
        assert parsed.year >= 2025
