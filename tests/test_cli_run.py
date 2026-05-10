"""Tests for ``expose run start`` CLI command and seed-type auto-detection."""

from __future__ import annotations

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
