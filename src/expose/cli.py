"""EXPOSE command-line interface.

Subcommands:

- ``expose run start <seed> --tenant <id>`` — execute an in-process pipeline run
- ``expose run status <run_id> --tenant <id>`` — look up a run's state
- ``expose run list --tenant <id>`` — list recent runs for a tenant
- ``expose artifact list --tenant <id>`` — list artifacts from past runs (future)
- ``expose scope validate <file>`` — validate a tenant's authorization scope (future)
- ``expose eval run --provider <p> --model <m> --dataset <d>`` — Phase 2 LLM eval (future)
"""

from __future__ import annotations

import asyncio
import ipaddress
import sys
import time
import uuid
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import click

import expose.collectors.builtin  # noqa: F401  — trigger @register_collector decorators
from expose import __version__
from expose.collectors.base import Seed, SeedType
from expose.collectors.registry import DEFAULT_REGISTRY
from expose.collectors.tiers import CollectorTier
from expose.pipeline.seed_expansion import expand_seeds

# === Seed-type auto-detection ================================================


def detect_seed_type(value: str) -> SeedType:
    """Auto-detect the seed type from a raw string value.

    Detection order: IP address, then CIDR network, then fallback to domain.
    """
    # Try IP first
    try:
        ipaddress.ip_address(value)
        return SeedType.IP
    except ValueError:
        pass
    # Try CIDR
    try:
        ipaddress.ip_network(value, strict=False)
        return SeedType.CIDR
    except ValueError:
        pass
    # Default to domain
    return SeedType.DOMAIN


# === In-memory run store (CLI demo path) =====================================


class _RunRecord:
    """Lightweight in-memory run record for the CLI demo path.

    Avoids importing SQLAlchemy / async session machinery that requires a
    real Postgres connection. The CLI stores runs in a module-level dict
    keyed by ``(tenant_id, run_id)`` so ``run status`` and ``run list``
    can look them up within the same process invocation.
    """

    __slots__ = (
        "collector_ids",
        "completed_at",
        "denied_dispatches",
        "duration_ms",
        "expanded_seeds",
        "failed_dispatches",
        "run_id",
        "seeds",
        "started_at",
        "state",
        "successful_dispatches",
        "tenant_id",
        "total_dispatches",
        "total_observations",
        "total_seeds",
    )

    def __init__(
        self,
        *,
        run_id: UUID,
        tenant_id: UUID,
        state: str,
        seeds: list[str],
        collector_ids: list[str],
        started_at: datetime,
    ) -> None:
        self.run_id = run_id
        self.tenant_id = tenant_id
        self.state = state
        self.seeds = seeds
        self.collector_ids = collector_ids
        self.started_at = started_at
        self.completed_at: datetime | None = None
        self.total_seeds: int = 0
        self.expanded_seeds: int = 0
        self.total_dispatches: int = 0
        self.successful_dispatches: int = 0
        self.failed_dispatches: int = 0
        self.denied_dispatches: int = 0
        self.total_observations: int = 0
        self.duration_ms: float = 0.0


# Module-level store: ``{(tenant_id, run_id): _RunRecord}``.
# Populated by ``run start``, queried by ``run status`` and ``run list``.
_run_store: dict[tuple[UUID, UUID], _RunRecord] = {}


def _get_tier1_collector_ids() -> list[str]:
    """Return collector IDs for all registered Tier-1 collectors."""
    return [cls.collector_id for cls in DEFAULT_REGISTRY.by_tier(CollectorTier.TIER_1)]


async def _execute_stub_run(
    *,
    run_id: UUID,
    tenant_id: UUID,
    seeds: list[Seed],
    collector_ids: list[str],
) -> dict[str, Any]:
    """In-process stub pipeline execution for the CLI demo path.

    Since the real ``RunRepository`` and ``EntityRepository`` require an
    async Postgres session, this stub uses a simplified synchronous flow
    that mirrors the executor's logic without the ORM.
    """
    start_ns = time.monotonic_ns()
    expanded = expand_seeds(seeds)

    successful = 0
    failed = 0
    denied = 0
    total_observations = 0
    collector_results: list[dict[str, Any]] = []

    for seed_item in expanded:
        for cid in collector_ids:
            if not DEFAULT_REGISTRY.is_registered(cid):
                failed += 1
                collector_results.append({
                    "collector_id": cid,
                    "seed": seed_item.value,
                    "status": "not_registered",
                    "observations": 0,
                })
                continue

            # For the demo path, record the dispatch as successful without
            # actually calling the upstream APIs (no network, no credentials).
            successful += 1
            collector_results.append({
                "collector_id": cid,
                "seed": seed_item.value,
                "status": "success",
                "observations": 0,
            })

    total_dispatches = successful + failed + denied
    if total_dispatches == 0 or (successful > 0 and failed == 0):
        final_state = "completed"
    elif successful > 0 and failed > 0:
        final_state = "partial"
    else:
        final_state = "failed"

    duration_ms = (time.monotonic_ns() - start_ns) / 1_000_000

    return {
        "run_id": run_id,
        "tenant_id": tenant_id,
        "final_state": final_state,
        "total_seeds": len(seeds),
        "expanded_seeds": len(expanded),
        "total_dispatches": total_dispatches,
        "successful_dispatches": successful,
        "failed_dispatches": failed,
        "denied_dispatches": denied,
        "total_observations": total_observations,
        "duration_ms": duration_ms,
        "collector_results": collector_results,
    }


# === CLI definition ==========================================================


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="expose")
def main() -> None:
    """EXPOSE -- external attack surface intelligence pipeline."""


# --- ``expose run`` subgroup -------------------------------------------------


@main.group()
def run() -> None:
    """Pipeline run management."""


@run.command("start")
@click.argument("seed")
@click.option(
    "--tenant",
    required=True,
    type=click.UUID,
    help="Tenant UUID for this run.",
)
@click.option(
    "--collector",
    "collectors",
    multiple=True,
    help="Collector ID to use (repeatable). Defaults to all Tier-1 collectors.",
)
@click.option(
    "--seed-type",
    type=click.Choice(
        [st.value for st in SeedType],
        case_sensitive=False,
    ),
    default=None,
    help="Seed type override. Auto-detected if omitted.",
)
def run_start(
    seed: str,
    tenant: UUID,
    collectors: tuple[str, ...],
    seed_type: str | None,
) -> None:
    """Start a pipeline run for SEED (domain, IP, or CIDR).

    Examples:

      expose run start example.com --tenant 00000000-0000-0000-0000-000000000001

      expose run start 192.168.1.0/24 --tenant <uuid> --collector ct-crtsh
    """
    # Determine seed type
    resolved_type = SeedType(seed_type) if seed_type is not None else detect_seed_type(seed)

    # Determine collector IDs
    collector_ids = list(collectors) if collectors else _get_tier1_collector_ids()

    # Build the seed object
    seed_obj = Seed(seed_type=resolved_type, value=seed)

    # Generate run ID
    run_id = uuid.uuid4()

    # Execute the stub pipeline
    result = asyncio.run(
        _execute_stub_run(
            run_id=run_id,
            tenant_id=tenant,
            seeds=[seed_obj],
            collector_ids=collector_ids,
        )
    )

    # Store the run record for later status/list queries
    now = datetime.now(tz=UTC)
    record = _RunRecord(
        run_id=run_id,
        tenant_id=tenant,
        state=result["final_state"],
        seeds=[seed],
        collector_ids=collector_ids,
        started_at=now,
    )
    record.completed_at = now
    record.total_seeds = result["total_seeds"]
    record.expanded_seeds = result["expanded_seeds"]
    record.total_dispatches = result["total_dispatches"]
    record.successful_dispatches = result["successful_dispatches"]
    record.failed_dispatches = result["failed_dispatches"]
    record.denied_dispatches = result["denied_dispatches"]
    record.total_observations = result["total_observations"]
    record.duration_ms = result["duration_ms"]
    _run_store[(tenant, run_id)] = record

    # Print summary table
    click.echo(f"\nRun ID:   {run_id}")
    click.echo(f"Tenant:   {tenant}")
    click.echo(f"Seed:     {seed} ({resolved_type.value})")
    click.echo(f"State:    {result['final_state']}")
    click.echo("")
    click.echo(f"  Seeds (original):   {result['total_seeds']}")
    click.echo(f"  Seeds (expanded):   {result['expanded_seeds']}")
    click.echo(f"  Dispatches:         {result['total_dispatches']}")
    click.echo(f"  Successful:         {result['successful_dispatches']}")
    click.echo(f"  Failed:             {result['failed_dispatches']}")
    click.echo(f"  Denied:             {result['denied_dispatches']}")
    click.echo(f"  Observations:       {result['total_observations']}")
    click.echo(f"  Duration:           {result['duration_ms']:.1f} ms")

    # Per-collector breakdown
    collector_results: list[dict[str, Any]] = result.get("collector_results", [])
    if collector_results:
        click.echo("")
        click.echo("  Collector Results:")
        click.echo(f"  {'Collector':<30} {'Seed':<30} {'Status':<20} {'Obs':>4}")
        click.echo(f"  {'-' * 30} {'-' * 30} {'-' * 20} {'-' * 4}")
        for cr in collector_results:
            click.echo(
                f"  {cr['collector_id']:<30} "
                f"{cr['seed']:<30} "
                f"{cr['status']:<20} "
                f"{cr['observations']:>4}"
            )


@run.command("status")
@click.argument("run_id", type=click.UUID)
@click.option(
    "--tenant",
    required=True,
    type=click.UUID,
    help="Tenant UUID.",
)
def run_status(run_id: UUID, tenant: UUID) -> None:
    """Show the status of a pipeline run."""
    key = (tenant, run_id)
    record = _run_store.get(key)

    if record is None:
        click.echo(f"No run found: run_id={run_id} tenant={tenant}", err=True)
        raise SystemExit(1)

    click.echo(f"\nRun ID:   {record.run_id}")
    click.echo(f"Tenant:   {record.tenant_id}")
    click.echo(f"State:    {record.state}")
    click.echo(f"Started:  {record.started_at.isoformat()}")
    if record.completed_at:
        click.echo(f"Completed: {record.completed_at.isoformat()}")
    click.echo("")
    click.echo(f"  Seeds (original):   {record.total_seeds}")
    click.echo(f"  Seeds (expanded):   {record.expanded_seeds}")
    click.echo(f"  Dispatches:         {record.total_dispatches}")
    click.echo(f"  Successful:         {record.successful_dispatches}")
    click.echo(f"  Failed:             {record.failed_dispatches}")
    click.echo(f"  Denied:             {record.denied_dispatches}")
    click.echo(f"  Observations:       {record.total_observations}")
    click.echo(f"  Duration:           {record.duration_ms:.1f} ms")
    click.echo(f"  Collectors:         {', '.join(record.collector_ids)}")


@run.command("list")
@click.option(
    "--tenant",
    required=True,
    type=click.UUID,
    help="Tenant UUID.",
)
def run_list(tenant: UUID) -> None:
    """List recent pipeline runs for a tenant."""
    runs = [
        r for (tid, _rid), r in _run_store.items()
        if tid == tenant
    ]
    # Sort by started_at descending
    runs.sort(key=lambda r: r.started_at, reverse=True)

    if not runs:
        click.echo(f"No runs found for tenant {tenant}.")
        return

    click.echo(f"\nRuns for tenant {tenant}:\n")
    click.echo(
        f"  {'Run ID':<38} {'State':<12} {'Seeds':>5} "
        f"{'Dispatches':>10} {'Obs':>4} {'Duration':>10}"
    )
    click.echo(
        f"  {'-' * 38} {'-' * 12} {'-' * 5} "
        f"{'-' * 10} {'-' * 4} {'-' * 10}"
    )
    for r in runs:
        click.echo(
            f"  {r.run_id!s:<38} {r.state:<12} {r.total_seeds:>5} "
            f"{r.total_dispatches:>10} {r.total_observations:>4} "
            f"{r.duration_ms:>8.1f}ms"
        )


if __name__ == "__main__":
    sys.exit(main())
