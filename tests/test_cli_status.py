"""Tests for ``expose run status`` and ``expose run list`` CLI commands."""

from __future__ import annotations

import re
from uuid import UUID, uuid4

from click.testing import CliRunner

from expose.cli import main

TENANT_UUID = "00000000-0000-0000-0000-000000000001"


def _start_run(runner: CliRunner, seed: str = "example.com") -> UUID:
    """Helper: start a run and extract the run_id from output."""
    result = runner.invoke(
        main,
        ["run", "start", seed, "--tenant", TENANT_UUID],
    )
    assert result.exit_code == 0, result.output
    # Extract the UUID after "Run ID:"
    match = re.search(r"Run ID:\s+([0-9a-f-]{36})", result.output)
    assert match is not None, f"Could not extract run_id from: {result.output}"
    return UUID(match.group(1))


class TestRunStatus:
    """Tests for ``expose run status``."""

    def test_status_exits_zero_for_existing_run(self) -> None:
        """``expose run status <id> --tenant <uuid>`` exits 0 for a known run."""
        runner = CliRunner()
        run_id = _start_run(runner)

        result = runner.invoke(
            main,
            ["run", "status", str(run_id), "--tenant", TENANT_UUID],
        )
        assert result.exit_code == 0, result.output
        assert "Run ID:" in result.output
        assert str(run_id) in result.output

    def test_status_missing_tenant_exits_nonzero(self) -> None:
        """Missing --tenant flag causes a non-zero exit."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["run", "status", str(uuid4())],
        )
        assert result.exit_code != 0

    def test_status_invalid_run_id_exits_nonzero(self) -> None:
        """An unknown run_id exits with code 1 and prints an error."""
        runner = CliRunner()
        fake_id = str(uuid4())
        result = runner.invoke(
            main,
            ["run", "status", fake_id, "--tenant", TENANT_UUID],
        )
        assert result.exit_code == 1
        assert "No run found" in result.output

    def test_status_shows_state_and_collectors(self) -> None:
        """Status output includes state and collector list."""
        runner = CliRunner()
        run_id = _start_run(runner)

        result = runner.invoke(
            main,
            ["run", "status", str(run_id), "--tenant", TENANT_UUID],
        )
        assert result.exit_code == 0, result.output
        assert "State:" in result.output
        assert "Collectors:" in result.output


class TestRunList:
    """Tests for ``expose run list``."""

    def test_list_exits_zero(self) -> None:
        """``expose run list --tenant <uuid>`` exits 0."""
        runner = CliRunner()
        # Start a run so there is at least one to list
        _start_run(runner)

        result = runner.invoke(
            main,
            ["run", "list", "--tenant", TENANT_UUID],
        )
        assert result.exit_code == 0, result.output

    def test_list_missing_tenant_exits_nonzero(self) -> None:
        """Missing --tenant flag causes a non-zero exit."""
        runner = CliRunner()
        result = runner.invoke(main, ["run", "list"])
        assert result.exit_code != 0

    def test_list_empty_tenant_shows_message(self) -> None:
        """Listing runs for a tenant with no runs prints a message."""
        runner = CliRunner()
        empty_tenant = str(uuid4())
        result = runner.invoke(
            main,
            ["run", "list", "--tenant", empty_tenant],
        )
        assert result.exit_code == 0, result.output
        assert "No runs found" in result.output

    def test_list_shows_run_after_start(self) -> None:
        """After starting a run, ``run list`` shows it."""
        runner = CliRunner()
        run_id = _start_run(runner, seed="list-test.example.com")

        result = runner.invoke(
            main,
            ["run", "list", "--tenant", TENANT_UUID],
        )
        assert result.exit_code == 0, result.output
        assert str(run_id) in result.output
