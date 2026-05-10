"""EXPOSE command-line interface.

Subcommands land as the engine matures (Sprint 3+):

- `expose run trigger --tenant <id>` — enqueue a manual run
- `expose artifact list --tenant <id>` — list artifacts from past runs
- `expose scope validate <file>` — validate a tenant's authorization scope
- `expose eval run --provider <p> --model <m> --dataset <d>` — Phase 2 LLM eval

Sprint 1-2 ships only `expose --version` as a smoke test.
"""
import sys

import click

from expose import __version__


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="expose")
def main() -> None:
    """EXPOSE — external attack surface intelligence pipeline."""


if __name__ == "__main__":
    sys.exit(main())
