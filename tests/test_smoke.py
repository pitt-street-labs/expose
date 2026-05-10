"""Trivial smoke tests confirming the package imports and the CLI runs."""
from click.testing import CliRunner

from expose import __version__
from expose.cli import main


def test_package_version_string() -> None:
    """`expose.__version__` is a non-empty PEP 440 string."""
    assert isinstance(__version__, str)
    assert len(__version__) > 0


def test_cli_version_command() -> None:
    """`expose --version` prints a version line."""
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "expose" in result.output.lower() or __version__ in result.output


def test_cli_help_command() -> None:
    """`expose --help` exits cleanly."""
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
