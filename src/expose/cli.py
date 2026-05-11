"""EXPOSE command-line interface.

Subcommands:

- ``expose serve`` — start the FastAPI HTTP server
- ``expose demo`` — run a quick end-to-end demo against a running API
- ``expose db upgrade`` — run Alembic migrations forward
- ``expose db downgrade`` — run Alembic migrations backward
- ``expose db current`` — show current migration revision
- ``expose run start <seed> --tenant <id>`` — execute an in-process pipeline run
- ``expose run start <seed> --tenant <id> --live`` — execute against a real Postgres
- ``expose run status <run_id> --tenant <id>`` — look up a run's state
- ``expose run list --tenant <id>`` — list recent runs for a tenant
- ``expose artifact list --tenant <id>`` — list artifacts from past runs (future)
- ``expose scope validate <file>`` — validate a tenant's authorization scope (future)
- ``expose eval --dataset <category> --rulepack <file>`` — run eval harness against a dataset
- ``expose eval --all --rulepack <file>`` — run eval harness against all datasets
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


# === Live pipeline execution (real Postgres + dispatcher) =====================

_LIVE_DB_ERROR = (
    "ERROR: Cannot connect to Postgres.\n"
    "\n"
    "Set the following environment variables (or rely on defaults):\n"
    "  EXPOSE_DB_HOST      (default: localhost)\n"
    "  EXPOSE_DB_PORT      (default: 5432)\n"
    "  EXPOSE_DB_DATABASE   (default: expose)\n"
    "  EXPOSE_DB_USER      (default: expose)\n"
    "  EXPOSE_DB_PASSWORD   (default: empty)\n"
    "\n"
    "Then ensure the database is running and accessible."
)


async def _execute_live_run(
    *,
    tenant_id: UUID,
    seeds: list[Seed],
    collector_ids: list[str],
) -> dict[str, Any]:
    """Execute a real pipeline run via RunExecutor + PipelineDispatcher.

    Requires a running Postgres database configured via ``EXPOSE_DB_*``
    environment variables. Raises ``SystemExit(1)`` with a descriptive
    error if the database is unreachable.
    """
    # Late imports to avoid pulling DB/pipeline machinery for the stub path.
    from expose.collectors.tiers import TenantAuthorizationScope  # noqa: PLC0415
    from expose.db.engine import (  # noqa: PLC0415
        DatabaseSettings,
        create_async_engine_from_settings,
        create_session_factory,
        session_scope,
    )
    from expose.egress.direct import DirectEgressProfile  # noqa: PLC0415
    from expose.pipeline.dispatcher import PipelineDispatcher  # noqa: PLC0415
    from expose.pipeline.run_executor import RunExecutor  # noqa: PLC0415
    from expose.repositories.entity_repo import EntityRepository  # noqa: PLC0415
    from expose.repositories.run_repo import RunRepository  # noqa: PLC0415
    from expose.types.shared import TenantId  # noqa: PLC0415

    try:
        settings = DatabaseSettings()
    except Exception:
        click.echo(click.style(_LIVE_DB_ERROR, fg="red"), err=True)
        raise SystemExit(1)  # noqa: B904

    try:
        engine = create_async_engine_from_settings(settings)
    except Exception:
        click.echo(click.style(_LIVE_DB_ERROR, fg="red"), err=True)
        raise SystemExit(1)  # noqa: B904

    factory = create_session_factory(engine)

    try:
        async with session_scope(factory) as session:
            run_repo = RunRepository(session)
            entity_repo = EntityRepository(session)

            # Create the run row in ``pending`` state.
            run = await run_repo.create(
                tenant_id=TenantId(tenant_id),
                pipeline_version=__version__,
            )

            # Build tenant authorization scope from the seed values.
            seed_identifiers = frozenset(s.value for s in seeds)
            scope = TenantAuthorizationScope(
                explicit_entity_identifiers=seed_identifiers,
            )

            # Wire credential resolver from the secrets backend so CLI
            # runs pick up API keys stored via the credential import API.
            from expose.api.credentials import _backend as secrets_backend  # noqa: PLC0415
            from expose.pipeline.credential_resolver import CredentialResolver  # noqa: PLC0415

            credential_resolver = CredentialResolver(secrets_backend)

            dispatcher = PipelineDispatcher(
                registry=DEFAULT_REGISTRY,
                tenant_scope=scope,
                tenant_id=tenant_id,
                egress_profile=DirectEgressProfile(),
                credential_resolver=credential_resolver,
            )

            # PipelineDispatcher satisfies DispatcherProtocol at runtime (both
            # DispatchJob/DispatchResult pairs are structurally identical) but
            # mypy sees them as distinct nominal types because they are
            # redefined in run_executor.py to avoid a circular import.
            executor = RunExecutor(
                dispatcher=dispatcher,  # type: ignore[arg-type]
                run_repo=run_repo,
                entity_repo=entity_repo,
            )

            result = await executor.execute(
                run_id=run.id,
                tenant_id=tenant_id,
                seeds=seeds,
                collector_ids=collector_ids,
            )

        return {
            "run_id": result.run_id,
            "tenant_id": result.tenant_id,
            "final_state": result.final_state,
            "total_seeds": result.total_seeds,
            "expanded_seeds": result.expanded_seeds,
            "total_dispatches": result.total_dispatches,
            "successful_dispatches": result.successful_dispatches,
            "failed_dispatches": result.failed_dispatches,
            "denied_dispatches": result.denied_dispatches,
            "total_observations": result.total_observations,
            "duration_ms": result.duration_ms,
            "collector_results": [],
        }
    except SystemExit:
        raise
    except Exception as exc:
        click.echo(
            click.style(f"{_LIVE_DB_ERROR}\nDetail: {exc}", fg="red"),
            err=True,
        )
        raise SystemExit(1) from exc
    finally:
        await engine.dispose()


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
@click.option(
    "--live",
    is_flag=True,
    default=False,
    help="Use real pipeline with Postgres persistence (requires EXPOSE_DB_* env vars).",
)
def run_start(
    seed: str,
    tenant: UUID,
    collectors: tuple[str, ...],
    seed_type: str | None,
    *,
    live: bool,
) -> None:
    """Start a pipeline run for SEED (domain, IP, or CIDR).

    Examples:

      expose run start example.com --tenant 00000000-0000-0000-0000-000000000001

      expose run start example.com --tenant <uuid> --live

      expose run start 192.168.1.0/24 --tenant <uuid> --collector ct-crtsh
    """
    # Determine seed type
    resolved_type = SeedType(seed_type) if seed_type is not None else detect_seed_type(seed)

    # Determine collector IDs
    collector_ids = list(collectors) if collectors else _get_tier1_collector_ids()

    # Build the seed object
    seed_obj = Seed(seed_type=resolved_type, value=seed)

    if live:
        # Live mode — real pipeline execution against Postgres.
        click.echo(click.style(
            "Running in live mode — using real pipeline with database persistence.",
            fg="green",
        ))

        result = asyncio.run(
            _execute_live_run(
                tenant_id=tenant,
                seeds=[seed_obj],
                collector_ids=collector_ids,
            )
        )

        run_id: UUID = result["run_id"]
    else:
        # Stub mode — simulated results, no network or persistence.
        run_id = uuid.uuid4()

        click.echo(click.style(
            "WARNING: Running in stub mode — no real collector calls, "
            "no database persistence. Results are simulated.",
            fg="yellow",
        ))

        result = asyncio.run(
            _execute_stub_run(
                run_id=run_id,
                tenant_id=tenant,
                seeds=[seed_obj],
                collector_ids=collector_ids,
            )
        )

        # Store the run record for later status/list queries (stub only).
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


# --- ``expose demo`` command --------------------------------------------------


@main.command()
@click.option("--host", default="localhost", help="API host.")
@click.option("--port", default=8090, type=int, help="API port.")
def demo(host: str, port: int) -> None:
    """Run a quick demo: create tenant, scan example.com, show results.

    Requires a running EXPOSE API server (``expose serve``).
    """
    import httpx  # noqa: PLC0415

    base = f"http://{host}:{port}"

    # 1. Health check
    click.echo("Checking API...")
    try:
        resp = httpx.get(f"{base}/healthz", timeout=5.0)
        resp.raise_for_status()
    except Exception as exc:
        click.echo(f"API not available at {base}: {exc}", err=True)
        click.echo("Start the server first: expose serve", err=True)
        raise SystemExit(1) from exc

    click.echo(f"API ready at {base}")

    # 2. Create tenant
    click.echo("\nCreating demo tenant...")
    tenant_name = f"demo-{uuid.uuid4().hex[:8]}"
    resp = httpx.post(f"{base}/v1/tenants/", json={"name": tenant_name})
    resp.raise_for_status()
    tenant_id = resp.json()["id"]
    click.echo(f"  Tenant: {tenant_id} ({tenant_name})")

    # 3. Trigger scan
    click.echo("\nScanning example.com...")
    resp = httpx.post(
        f"{base}/v1/tenants/{tenant_id}/runs",
        json={"seeds": ["example.com"]},
    )
    resp.raise_for_status()
    run_id = resp.json()["run_id"]
    click.echo(f"  Run: {run_id}")

    # 4. Poll until terminal state (max 60 s)
    state = "pending"
    for _ in range(30):
        resp = httpx.get(f"{base}/v1/tenants/{tenant_id}/runs/{run_id}")
        resp.raise_for_status()
        state = resp.json()["state"]
        if state in ("completed", "partial", "failed"):
            break
        click.echo(f"  State: {state}...")
        time.sleep(2)

    # 5. Results
    click.echo(f"\nFinal state: {state}")
    resp = httpx.get(f"{base}/v1/tenants/{tenant_id}/entities")
    resp.raise_for_status()
    entities = resp.json()
    count = len(entities.get("entities", entities.get("items", [])))
    click.echo(f"Discovered entities: {count}")
    click.echo(f"\nDashboard: http://{host}:{port}/")


# --- ``expose serve`` command -------------------------------------------------


@main.command()
@click.option(
    "--host",
    default="0.0.0.0",  # noqa: S104
    show_default=True,
    help="Bind address.",
)
@click.option(
    "--port",
    default=8090,
    show_default=True,
    type=int,
    help="Listen port.",
)
@click.option(
    "--reload",
    "reload_flag",
    is_flag=True,
    default=False,
    help="Enable auto-reload (development only).",
)
@click.option(
    "--no-otel",
    is_flag=True,
    default=False,
    help="Disable OpenTelemetry observability.",
)
def serve(host: str, port: int, *, reload_flag: bool, no_otel: bool) -> None:
    """Start the EXPOSE API HTTP server.

    Launches uvicorn with the application factory.  Use ``--reload`` for
    development and ``--no-otel`` to silence OTel console output locally.
    """
    import uvicorn  # noqa: PLC0415

    # When --reload is active uvicorn needs the import string so it can
    # re-import after file changes.  Without --reload we can pass the
    # pre-built app directly for faster startup.
    if reload_flag:
        # Set the flag via env so the factory picks it up on reload.
        import os  # noqa: PLC0415

        if no_otel:
            os.environ["EXPOSE_NO_OTEL"] = "1"
        uvicorn.run(
            "expose.api.app:create_app",
            factory=True,
            host=host,
            port=port,
            reload=True,
        )
    else:
        from expose.api.app import create_app  # noqa: PLC0415

        app = create_app(enable_otel=not no_otel)
        uvicorn.run(app, host=host, port=port)


# --- ``expose db`` subgroup ---------------------------------------------------


@main.group()
def db() -> None:
    """Database migration management (Alembic)."""


def _alembic_config() -> Any:
    """Build an Alembic ``Config`` pointing at the project's alembic.ini.

    Resolution order:
      1. Source-tree relative (``cli.py`` -> ``src/expose/`` -> 3x parent =
         project root) — works during development.
      2. ``$PWD/alembic.ini`` — works in the Docker container where WORKDIR is
         ``/app`` and alembic.ini is copied there.
      3. ``/app/alembic.ini`` — absolute fallback for container deployments
         where CWD might differ from ``/app``.

    Raises ``FileNotFoundError`` if none of the candidates exist, with a
    diagnostic message listing the paths tried.
    """
    from pathlib import Path  # noqa: PLC0415

    from alembic.config import Config  # noqa: PLC0415

    candidates = [
        Path(__file__).resolve().parent.parent.parent / "alembic.ini",
        Path.cwd() / "alembic.ini",
        Path("/app/alembic.ini"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return Config(str(candidate))

    tried = ", ".join(str(c) for c in candidates)
    msg = f"alembic.ini not found; searched: {tried}"
    raise FileNotFoundError(msg)


@db.command()
@click.option(
    "--revision",
    default="head",
    show_default=True,
    help="Target revision (e.g. 'head', '+1', a specific hash).",
)
def upgrade(revision: str) -> None:
    """Run database migrations forward to REVISION."""
    from alembic import command as alembic_cmd  # noqa: PLC0415

    cfg = _alembic_config()
    click.echo(f"Upgrading database to revision: {revision}")
    alembic_cmd.upgrade(cfg, revision)
    click.echo("Done.")


@db.command()
@click.option(
    "--revision",
    default="-1",
    show_default=True,
    help="Target revision (e.g. '-1', 'base', a specific hash).",
)
def downgrade(revision: str) -> None:
    """Run database migrations backward to REVISION."""
    from alembic import command as alembic_cmd  # noqa: PLC0415

    cfg = _alembic_config()
    click.echo(f"Downgrading database to revision: {revision}")
    alembic_cmd.downgrade(cfg, revision)
    click.echo("Done.")


@db.command()
def current() -> None:
    """Show the current database migration revision."""
    from alembic import command as alembic_cmd  # noqa: PLC0415

    cfg = _alembic_config()
    alembic_cmd.current(cfg, verbose=True)


# --- ``expose eval`` command --------------------------------------------------

# Default accuracy threshold for exit code determination.
_EVAL_PASS_THRESHOLD = 0.80


@main.command("eval")
@click.option(
    "--dataset",
    "dataset_name",
    type=click.Choice(
        ["confirmed_yours", "confirmed_not_yours", "ambiguous", "adversarial"],
        case_sensitive=False,
    ),
    default=None,
    help="Eval dataset category to run.  Mutually exclusive with --all.",
)
@click.option(
    "--all",
    "run_all",
    is_flag=True,
    default=False,
    help="Run evaluation against all four dataset categories.",
)
@click.option(
    "--rulepack",
    "rulepack_path",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="Path to a RulePack JSON file.  When omitted the built-in stub is used.",
)
@click.option(
    "--dataset-dir",
    "dataset_dir",
    type=click.Path(exists=True, file_okay=False),
    default=None,
    help="Directory containing eval dataset JSON files. "
    "Defaults to examples/eval-datasets/ relative to the project root.",
)
@click.option(
    "--threshold",
    type=float,
    default=_EVAL_PASS_THRESHOLD,
    show_default=True,
    help="Minimum overall accuracy to pass (exit code 0).",
)
@click.option(
    "--json-output",
    "json_output",
    is_flag=True,
    default=False,
    help="Emit the full EvalReport as JSON instead of human-readable text.",
)
def eval_cmd(
    dataset_name: str | None,
    *,
    run_all: bool,
    rulepack_path: str | None,
    dataset_dir: str | None,
    threshold: float,
    json_output: bool,
) -> None:
    """Run the EXPOSE attribution eval harness.

    Evaluates an attribution function against curated datasets and reports
    accuracy, precision, recall, F1, and a confusion matrix.

    Examples:

      expose eval --dataset confirmed_yours

      expose eval --all --rulepack examples/rulepacks/example-baseline.json

      expose eval --all --json-output

    Exit code 0 if overall accuracy >= threshold (default 80%), 1 otherwise.
    """
    import json as json_mod  # noqa: PLC0415
    from pathlib import Path  # noqa: PLC0415

    from expose.eval.datasets import (  # noqa: PLC0415
        EVAL_CATEGORIES,
        load_dataset_by_category,
        load_datasets_by_categories,
    )
    from expose.eval.runner import EvalRunner  # noqa: PLC0415

    # --- Validate mutually exclusive options ---
    if not dataset_name and not run_all:
        click.echo(
            click.style(
                "ERROR: Specify --dataset <category> or --all.", fg="red",
            ),
            err=True,
        )
        raise SystemExit(2)

    if dataset_name and run_all:
        click.echo(
            click.style(
                "ERROR: --dataset and --all are mutually exclusive.", fg="red",
            ),
            err=True,
        )
        raise SystemExit(2)

    # --- Resolve dataset directory ---
    if dataset_dir:
        ds_dir = Path(dataset_dir)
    else:
        # Default: project root / examples / eval-datasets
        # cli.py lives at src/expose/cli.py -> 3 parents up = project root
        ds_dir = Path(__file__).resolve().parent.parent.parent / "examples" / "eval-datasets"

    if not ds_dir.is_dir():
        click.echo(
            click.style(f"ERROR: Dataset directory not found: {ds_dir}", fg="red"),
            err=True,
        )
        raise SystemExit(2)

    # --- Load datasets ---
    if run_all:
        categories = list(EVAL_CATEGORIES)
        datasets = load_datasets_by_categories(ds_dir, categories)
    else:
        datasets = [load_dataset_by_category(ds_dir, dataset_name)]  # type: ignore[arg-type]

    # --- Build the runner ---
    runner: EvalRunner
    if rulepack_path:
        rp_path = Path(rulepack_path)
        rp_data = json_mod.loads(rp_path.read_text(encoding="utf-8"))
        # Strip $schema key if present (editor convention not in Pydantic model).
        rp_data.pop("$schema", None)

        from expose.pipeline.rule_evaluator import RuleEvaluator  # noqa: PLC0415
        from expose.types.rulepack import RulePack  # noqa: PLC0415

        pack = RulePack.model_validate(rp_data)
        evaluator = RuleEvaluator(pack)
        runner = EvalRunner.from_rule_evaluator(evaluator)
        click.echo(f"Using rulepack: {pack.pack_id} v{pack.pack_version}")
    else:
        runner = EvalRunner()
        click.echo("Using built-in stub attribution function.")

    # --- Run evaluation ---
    click.echo(f"Running {len(datasets)} dataset(s)...\n")
    report = asyncio.run(runner.run_report(datasets))

    # --- Output ---
    if json_output:
        click.echo(report.model_dump_json(indent=2))
    else:
        # Human-readable output.
        for ds_name, cat_report in report.categories.items():
            m = cat_report.metrics
            click.echo(f"=== {ds_name} ({cat_report.category}) ===")
            click.echo(f"  Cases:       {m.total_cases}")
            click.echo(f"  Correct:     {m.correct_attributions}")
            click.echo(f"  Accuracy:    {m.attribution_accuracy:.2%}")
            click.echo(f"  Precision:   {cat_report.precision:.2%}")
            click.echo(f"  Recall:      {cat_report.recall:.2%}")
            click.echo(f"  F1:          {cat_report.f1:.2%}")
            click.echo(f"  FP:          {m.false_positives}")
            click.echo(f"  FN:          {m.false_negatives}")
            click.echo(f"  Conf Error:  {m.mean_confidence_error:.4f}")
            click.echo(f"  Wall Clock:  {cat_report.total_wall_clock_ms:.1f} ms "
                        f"(mean {cat_report.mean_wall_clock_ms:.3f} ms/case)")
            click.echo()

        # Confusion matrix
        click.echo("=== Confusion Matrix (Expected vs Actual) ===")
        for line in report.confusion_matrix.display_lines():
            click.echo(f"  {line}")
        click.echo()

        # Overall
        click.echo("=== Overall ===")
        click.echo(f"  Total Cases:  {report.total_cases}")
        click.echo(f"  Accuracy:     {report.overall_accuracy:.2%}")
        click.echo(f"  Precision:    {report.overall_precision:.2%}")
        click.echo(f"  Recall:       {report.overall_recall:.2%}")
        click.echo(f"  F1:           {report.overall_f1:.2%}")
        click.echo(f"  Wall Clock:   {report.total_wall_clock_ms:.1f} ms")

    # --- Exit code ---
    if report.overall_accuracy >= threshold:
        click.echo(click.style(
            f"\nPASS: accuracy {report.overall_accuracy:.2%} >= {threshold:.2%}",
            fg="green",
        ))
    else:
        click.echo(click.style(
            f"\nFAIL: accuracy {report.overall_accuracy:.2%} < {threshold:.2%}",
            fg="red",
        ))
        raise SystemExit(1)


if __name__ == "__main__":
    sys.exit(main())
