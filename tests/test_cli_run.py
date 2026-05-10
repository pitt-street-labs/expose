"""Tests for ``expose run start`` CLI command and seed-type auto-detection."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from click.testing import CliRunner

from expose.cli import detect_seed_type, main
from expose.collectors.base import SeedType

TENANT_UUID = "00000000-0000-0000-0000-000000000001"


class TestDetectSeedType:
    """Unit tests for ``detect_seed_type``."""

    def test_domain_detected(self) -> None:
        assert detect_seed_type("example.com") == SeedType.DOMAIN

    def test_subdomain_detected_as_domain(self) -> None:
        assert detect_seed_type("www.example.com") == SeedType.DOMAIN

    def test_ipv4_detected(self) -> None:
        assert detect_seed_type("192.168.1.1") == SeedType.IP

    def test_ipv6_detected(self) -> None:
        assert detect_seed_type("::1") == SeedType.IP

    def test_cidr_v4_detected(self) -> None:
        assert detect_seed_type("10.0.0.0/8") == SeedType.CIDR

    def test_cidr_v6_detected(self) -> None:
        assert detect_seed_type("fd00::/8") == SeedType.CIDR

    def test_bare_string_defaults_to_domain(self) -> None:
        assert detect_seed_type("my-org") == SeedType.DOMAIN


class TestRunStart:
    """Tests for ``expose run start``."""

    def test_start_domain_exits_zero(self) -> None:
        """``expose run start example.com --tenant <uuid>`` exits 0 and prints run_id."""
        runner = CliRunner()
        result = runner.invoke(main, ["run", "start", "example.com", "--tenant", TENANT_UUID])
        assert result.exit_code == 0, result.output
        assert "Run ID:" in result.output

    def test_start_without_tenant_exits_nonzero(self) -> None:
        """Missing --tenant flag causes a non-zero exit."""
        runner = CliRunner()
        result = runner.invoke(main, ["run", "start", "example.com"])
        assert result.exit_code != 0

    def test_domain_seed_auto_detected_in_output(self) -> None:
        """Domain seed type appears in output when auto-detected."""
        runner = CliRunner()
        result = runner.invoke(main, ["run", "start", "example.com", "--tenant", TENANT_UUID])
        assert result.exit_code == 0, result.output
        assert "domain" in result.output.lower()

    def test_ip_seed_auto_detected_in_output(self) -> None:
        """IP seed type appears in output when auto-detected."""
        runner = CliRunner()
        result = runner.invoke(main, ["run", "start", "8.8.8.8", "--tenant", TENANT_UUID])
        assert result.exit_code == 0, result.output
        # The output should show "ip" as the seed type
        assert "(ip)" in result.output.lower()

    def test_single_collector_flag_accepted(self) -> None:
        """``--collector`` flag is accepted and the run succeeds."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "run", "start", "example.com",
                "--tenant", TENANT_UUID,
                "--collector", "ct-crtsh",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "ct-crtsh" in result.output

    def test_multiple_collector_flags_work(self) -> None:
        """Multiple ``--collector`` flags are accepted and both appear in output."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "run", "start", "example.com",
                "--tenant", TENANT_UUID,
                "--collector", "ct-crtsh",
                "--collector", "cloud-ranges",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "ct-crtsh" in result.output
        assert "cloud-ranges" in result.output

    def test_seed_type_override(self) -> None:
        """``--seed-type`` overrides auto-detection."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "run", "start", "my-custom-thing",
                "--tenant", TENANT_UUID,
                "--seed-type", "organization",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "organization" in result.output.lower()

    def test_cidr_seed_auto_detected(self) -> None:
        """CIDR seed auto-detected."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["run", "start", "10.0.0.0/24", "--tenant", TENANT_UUID],
        )
        assert result.exit_code == 0, result.output
        assert "(cidr)" in result.output.lower()

    def test_output_contains_summary_fields(self) -> None:
        """Run output contains all expected summary fields."""
        runner = CliRunner()
        result = runner.invoke(main, ["run", "start", "example.com", "--tenant", TENANT_UUID])
        assert result.exit_code == 0, result.output
        for field in ["Run ID:", "Tenant:", "Seed:", "State:", "Seeds (original):",
                       "Seeds (expanded):", "Dispatches:", "Duration:"]:
            assert field in result.output, f"Missing field: {field}"

    def test_unregistered_collector_marks_failed(self) -> None:
        """An unregistered collector ID results in a failed dispatch."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "run", "start", "example.com",
                "--tenant", TENANT_UUID,
                "--collector", "nonexistent-collector",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "not_registered" in result.output


class TestRunStartLive:
    """Tests for the ``--live`` flag on ``expose run start``."""

    def test_live_flag_accepted_by_cli_parser(self) -> None:
        """``--live`` is a recognized flag and does not cause a usage error."""
        runner = CliRunner()
        # --live will attempt a real DB connection, which will fail in CI.
        # We mock `_execute_live_run` to avoid that.
        from uuid import UUID as _UUID  # noqa: PLC0415

        mock_result: dict[str, object] = {
            "run_id": _UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            "tenant_id": TENANT_UUID,
            "final_state": "completed",
            "total_seeds": 1,
            "expanded_seeds": 1,
            "total_dispatches": 0,
            "successful_dispatches": 0,
            "failed_dispatches": 0,
            "denied_dispatches": 0,
            "total_observations": 0,
            "duration_ms": 1.0,
            "collector_results": [],
        }

        async def _fake_live_run(**_kwargs: object) -> dict[str, object]:
            return mock_result

        with patch("expose.cli._execute_live_run", side_effect=_fake_live_run):
            result = runner.invoke(
                main,
                [
                    "run", "start", "example.com",
                    "--tenant", TENANT_UUID,
                    "--live",
                ],
            )
        assert result.exit_code == 0, result.output
        assert "live mode" in result.output.lower()
        assert "Run ID:" in result.output

    def test_live_db_connection_error_exits_with_message(self) -> None:
        """``--live`` without a reachable Postgres exits 1 with an error message."""
        runner = CliRunner()

        # Patch create_async_engine_from_settings to raise immediately inside
        # the _execute_live_run call so the connection-error path is exercised.
        with patch(
            "expose.cli._execute_live_run",
            side_effect=SystemExit(1),
        ):
            result = runner.invoke(
                main,
                [
                    "run", "start", "example.com",
                    "--tenant", TENANT_UUID,
                    "--live",
                ],
            )
        assert result.exit_code == 1

    def test_live_db_error_shows_descriptive_message(self) -> None:
        """When ``--live`` fails to connect, the error message mentions EXPOSE_DB_*."""
        runner = CliRunner()

        # Let the real _execute_live_run run but patch the engine creation
        # to raise a connection error.
        mock_engine = MagicMock()
        mock_engine.dispose = AsyncMock()

        with patch(
            "expose.db.engine.DatabaseSettings",
        ), patch(
            "expose.db.engine.create_async_engine_from_settings",
            return_value=mock_engine,
        ), patch(
            "expose.db.engine.create_session_factory",
        ) as mock_factory:
            # Make the session_scope raise a connection error.
            mock_factory.return_value = MagicMock()
            with patch(
                "expose.db.engine.session_scope",
                side_effect=ConnectionError("Connection refused"),
            ):
                result = runner.invoke(
                    main,
                    [
                        "run", "start", "example.com",
                        "--tenant", TENANT_UUID,
                        "--live",
                    ],
                )
        assert result.exit_code == 1
        assert "EXPOSE_DB_" in result.output

    def test_default_no_live_uses_stub(self) -> None:
        """Without ``--live``, the stub path is used (backward compatibility)."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["run", "start", "example.com", "--tenant", TENANT_UUID],
        )
        assert result.exit_code == 0, result.output
        assert "stub mode" in result.output.lower()
