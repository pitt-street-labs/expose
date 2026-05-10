"""Tests for ``expose serve`` and ``expose db`` CLI commands.

Uses ``click.testing.CliRunner`` to exercise help output and option
parsing without starting a real uvicorn server or touching a database.
"""

from __future__ import annotations

from click.testing import CliRunner

from expose.cli import main


class TestServeCommand:
    """Tests for ``expose serve``."""

    def test_serve_help_shows_options(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["serve", "--help"])
        assert result.exit_code == 0, result.output
        assert "--host" in result.output
        assert "--port" in result.output
        assert "--reload" in result.output
        assert "--no-otel" in result.output

    def test_serve_help_shows_description(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["serve", "--help"])
        assert result.exit_code == 0, result.output
        assert "EXPOSE API" in result.output or "HTTP server" in result.output


class TestDbUpgradeCommand:
    """Tests for ``expose db upgrade``."""

    def test_upgrade_help_shows_options(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["db", "upgrade", "--help"])
        assert result.exit_code == 0, result.output
        assert "--revision" in result.output
        assert "head" in result.output

    def test_upgrade_help_shows_description(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["db", "upgrade", "--help"])
        assert result.exit_code == 0, result.output
        assert "migrations" in result.output.lower() or "REVISION" in result.output


class TestDbDowngradeCommand:
    """Tests for ``expose db downgrade``."""

    def test_downgrade_help_shows_options(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["db", "downgrade", "--help"])
        assert result.exit_code == 0, result.output
        assert "--revision" in result.output
        assert "-1" in result.output

    def test_downgrade_help_shows_description(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["db", "downgrade", "--help"])
        assert result.exit_code == 0, result.output
        assert "migrations" in result.output.lower() or "REVISION" in result.output


class TestDbCurrentCommand:
    """Tests for ``expose db current``."""

    def test_current_help_shows_description(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["db", "current", "--help"])
        assert result.exit_code == 0, result.output
        assert "current" in result.output.lower() or "revision" in result.output.lower()


class TestDbGroup:
    """Tests for the ``expose db`` command group itself."""

    def test_db_help_lists_subcommands(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["db", "--help"])
        assert result.exit_code == 0, result.output
        assert "upgrade" in result.output
        assert "downgrade" in result.output
        assert "current" in result.output
