"""FastAPI router serving the EXPOSE dashboard UI.

All routes return ``HTMLResponse`` rendered through Jinja2 templates.
HTMX partial endpoints live under ``/partials/`` and return HTML fragments
suitable for ``hx-swap``.

Static assets (CSS, JS) are mounted at ``/static/`` from the ``static/``
directory adjacent to this module.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# ---------------------------------------------------------------------------
# Paths — resolved relative to this module so the package is relocatable.
# ---------------------------------------------------------------------------

_UI_DIR = Path(__file__).resolve().parent
_TEMPLATES_DIR = _UI_DIR / "templates"
_STATIC_DIR = _UI_DIR / "static"

templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))


def _format_datetime(value: str | datetime | None) -> str:
    if not value:
        return "—"
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
    now = datetime.now(tz=timezone.utc)
    diff = now - value.replace(tzinfo=timezone.utc) if value.tzinfo is None else now - value
    minutes = int(diff.total_seconds() / 60)
    if minutes < 1:
        return "just now"
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h ago"
    days = hours // 24
    if days < 7:
        return f"{days}d ago"
    return value.strftime("%Y-%m-%d %H:%M")


templates.env.filters["format_dt"] = _format_datetime

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(tags=["ui"])


def mount_static(app: object) -> None:
    """Mount the ``/static/`` directory on *app*.

    Called during application startup so that CSS/JS assets are served.
    Accepts any object with a ``mount`` method (i.e., a ``FastAPI`` or
    ``Starlette`` application instance).

    Args:
        app: The FastAPI (or Starlette) application to mount static files on.
    """
    mount = getattr(app, "mount", None)
    if mount is None:  # pragma: no cover
        msg = "app must have a .mount() method"
        raise TypeError(msg)
    mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


# ---------------------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------------------


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    """Render the main dashboard page.

    When no tenant is selected the page renders an empty state prompting
    the user to choose one. Tenant and run data are loaded via HTMX
    partials after initial render.
    """
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"page_title": "Dashboard"},
    )


@router.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request) -> HTMLResponse:
    """Render the admin panel page.

    Provides tenant management, run management, credential health
    testing, and system-wide statistics in a single view.
    """
    return templates.TemplateResponse(
        request=request,
        name="admin.html",
        context={"page_title": "Admin"},
    )


@router.get("/runs/{run_id}", response_class=HTMLResponse)
async def run_detail(request: Request, run_id: UUID) -> HTMLResponse:
    """Render the detail view for a specific pipeline run.

    The run timeline and per-stage metrics are loaded as HTMX partials
    that poll for updates while the run is in progress.
    """
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"page_title": "Run Detail", "active_run_id": str(run_id)},
    )


# ---------------------------------------------------------------------------
# HTMX partial routes — return HTML fragments, not full pages
# ---------------------------------------------------------------------------


_PLACEHOLDER_ENTITIES = [
    {
        "id": "a1b2c3d4-0000-0000-0000-000000000001",
        "entity_type": "domain",
        "canonical_identifier": "example.com",
        "attribution_status": "confirmed",
        "properties": {
            "_collector_id": "rdap-whois",
            "_observation_type": "domain_registration",
            "_observed_at": "2026-05-10T12:30:00Z",
            "registrant_org": "Example Corp",
            "registrar": "Cloudflare, Inc.",
            "nameservers": ["ns1.cloudflare.com", "ns2.cloudflare.com"],
        },
        "first_observed_at": "2026-05-10T08:00:00Z",
        "last_observed_at": "2026-05-10T12:30:00Z",
    },
    {
        "id": "a1b2c3d4-0000-0000-0000-000000000002",
        "entity_type": "subdomain",
        "canonical_identifier": "api.example.com",
        "attribution_status": "high",
        "properties": {
            "_collector_id": "active-dns",
            "_observation_type": "dns_resolution",
            "_observed_at": "2026-05-10T12:30:00Z",
            "resolved_ips": ["203.0.113.42"],
            "record_type": "A",
        },
        "first_observed_at": "2026-05-10T08:15:00Z",
        "last_observed_at": "2026-05-10T12:30:00Z",
    },
    {
        "id": "a1b2c3d4-0000-0000-0000-000000000003",
        "entity_type": "ip",
        "canonical_identifier": "203.0.113.42",
        "attribution_status": "requires_review",
        "properties": {
            "_collector_id": "scan-shodan",
            "_observation_type": "port_scan",
            "_observed_at": "2026-05-10T12:30:00Z",
            "open_ports": [80, 443, 8080],
            "cloud_provider": "AWS",
        },
        "first_observed_at": "2026-05-10T09:00:00Z",
        "last_observed_at": "2026-05-10T12:30:00Z",
    },
    {
        "id": "a1b2c3d4-0000-0000-0000-000000000004",
        "entity_type": "subdomain",
        "canonical_identifier": "mail.example.com",
        "attribution_status": "medium",
        "properties": {
            "_collector_id": "email-auth",
            "_observation_type": "email_authentication",
            "_observed_at": "2026-05-10T12:30:00Z",
            "spf_ip4_addresses": ["198.51.100.7"],
            "dmarc_policy": "reject",
        },
        "first_observed_at": "2026-05-10T09:30:00Z",
        "last_observed_at": "2026-05-10T12:30:00Z",
    },
    {
        "id": "a1b2c3d4-0000-0000-0000-000000000005",
        "entity_type": "ip",
        "canonical_identifier": "198.51.100.7",
        "attribution_status": "confirmed",
        "properties": {
            "_collector_id": "cloud-ranges",
            "_observation_type": "cloud_range_match",
            "_observed_at": "2026-05-10T12:30:00Z",
            "cloud_provider": "GCP",
            "bucket_name": "example-prod-assets",
        },
        "first_observed_at": "2026-05-10T10:00:00Z",
        "last_observed_at": "2026-05-10T12:30:00Z",
    },
]


@router.get("/partials/entities", response_class=HTMLResponse)
async def entities_partial(request: Request, tenant_id: UUID) -> HTMLResponse:
    """Return the entity table partial for a given tenant.

    Called by HTMX on a 5-second poll cycle from the dashboard right pane.
    When a database session factory is available (production / integration
    tests) the entities are queried from the ``entities`` table; otherwise
    placeholder data is returned so the UI works in dev/test mode without
    a database.
    """
    session_factory = getattr(request.app.state, "session_factory", None)
    if session_factory is None:
        return templates.TemplateResponse(
            request=request,
            name="partials/entity_table.html",
            context={
                "entities": _PLACEHOLDER_ENTITIES,
                "tenant_id": str(tenant_id),
            },
        )

    from sqlalchemy import select  # noqa: PLC0415

    from expose.db.models import Entity  # noqa: PLC0415

    async with session_factory() as session:
        stmt = (
            select(Entity)
            .where(Entity.tenant_id == tenant_id)
            .order_by(Entity.last_observed_at.desc())
            .limit(100)
        )
        result = await session.execute(stmt)
        rows = result.scalars().all()

    entity_dicts = [
        {
            "id": str(e.id),
            "entity_type": e.entity_type,
            "canonical_identifier": e.canonical_identifier,
            "properties": e.properties or {},
            "attribution_status": e.attribution_status,
            "first_observed_at": (
                e.first_observed_at.isoformat() if e.first_observed_at else ""
            ),
            "last_observed_at": (
                e.last_observed_at.isoformat() if e.last_observed_at else ""
            ),
        }
        for e in rows
    ]

    return templates.TemplateResponse(
        request=request,
        name="partials/entity_table.html",
        context={"entities": entity_dicts, "tenant_id": str(tenant_id)},
    )


_PIPELINE_STAGES = [
    ("seed", "Seed"),
    ("collect", "Collect"),
    ("sanitize", "Sanitize"),
    ("attribute", "Attribute"),
    ("done", "Done"),
]

# Maps Run.state to the index of the currently active stage (0-based).
# Unknown states are treated as the first stage in pending mode.
_STATE_STAGE_INDEX: dict[str, int] = {
    "pending": 0,
    "seeding": 0,
    "collecting": 1,
    "sanitizing": 2,
    "attributing": 3,
    "completed": 4,
    "failed": -1,  # sentinel — handled separately
}

_PLACEHOLDER_RUN = {
    "id": "00000000-0000-0000-0000-000000000000",
    "state": "collecting",
    "started_at": "2026-05-10T12:00:00Z",
    "completed_at": None,
    "current_stage": "collect",
    "stages": [
        {"name": "seed", "label": "Seed", "status": "done"},
        {"name": "collect", "label": "Collect", "status": "active"},
        {"name": "sanitize", "label": "Sanitize", "status": "pending"},
        {"name": "attribute", "label": "Attribute", "status": "pending"},
        {"name": "done", "label": "Done", "status": "pending"},
    ],
    "entities_discovered": 47,
    "entities_attributed": 12,
    "elapsed_seconds": 134,
}


def _build_stages(state: str) -> list[dict[str, str]]:
    """Derive per-stage status dicts from a ``Run.state`` string.

    Stages before the current one are ``"done"``, the current one is
    ``"active"``, and later ones are ``"pending"``.  The ``"failed"``
    state marks every stage that was not yet completed as ``"failed"``.
    ``"completed"`` marks all stages as ``"done"``.
    """
    active_idx = _STATE_STAGE_INDEX.get(state, 0)
    stages: list[dict[str, str]] = []
    for i, (name, label) in enumerate(_PIPELINE_STAGES):
        if state == "failed":
            # Everything up to the last done stage stays done; the rest fail.
            # Heuristic: mark all stages pending (caller doesn't track which
            # stage failed, so the whole suffix is "failed").
            status = "failed"
        elif state == "completed" or i < active_idx:
            status = "done"
        elif i == active_idx:
            status = "active"
        else:
            status = "pending"
        stages.append({"name": name, "label": label, "status": status})
    return stages


@router.get("/partials/run-status/{run_id}", response_class=HTMLResponse)
async def run_status_partial(request: Request, run_id: UUID) -> HTMLResponse:
    """Return the run status bar partial.

    Called by HTMX on a 2-second poll cycle while a run is active.
    Displays pipeline stage progress (Seed -> Collect -> Sanitize ->
    Attribute -> Done).

    When a database session factory is available the run metadata and
    entity counts are queried live; otherwise placeholder data is
    returned for dev/test use.
    """
    session_factory = getattr(request.app.state, "session_factory", None)
    if session_factory is None:
        placeholder_run = {**_PLACEHOLDER_RUN, "id": str(run_id)}
        return templates.TemplateResponse(
            request=request,
            name="partials/run_status.html",
            context={"run": placeholder_run},
        )

    from datetime import UTC, datetime  # noqa: PLC0415

    from sqlalchemy import func, select  # noqa: PLC0415

    from expose.db.models import Entity, Run  # noqa: PLC0415

    async with session_factory() as session:
        stmt = select(Run).where(Run.id == run_id)
        result = await session.execute(stmt)
        run_row = result.scalar_one_or_none()

        if run_row is None:
            placeholder_run = {**_PLACEHOLDER_RUN, "id": str(run_id)}
            return templates.TemplateResponse(
                request=request,
                name="partials/run_status.html",
                context={"run": placeholder_run},
            )

        # Count total entities and attributed entities for this tenant/run.
        total_stmt = (
            select(func.count())
            .select_from(Entity)
            .where(Entity.tenant_id == run_row.tenant_id)
        )
        attributed_stmt = (
            select(func.count())
            .select_from(Entity)
            .where(
                Entity.tenant_id == run_row.tenant_id,
                Entity.attribution_status == "confirmed",
            )
        )
        total_result = await session.execute(total_stmt)
        attributed_result = await session.execute(attributed_stmt)
        entities_discovered = total_result.scalar_one()
        entities_attributed = attributed_result.scalar_one()

    now = datetime.now(tz=UTC)
    started = run_row.started_at
    if run_row.completed_at is not None:
        elapsed = (run_row.completed_at - started).total_seconds()
    elif started is not None:
        elapsed = (now - started).total_seconds()
    else:
        elapsed = 0
    elapsed_seconds = math.floor(elapsed)

    run_dict = {
        "id": str(run_row.id),
        "state": run_row.state,
        "started_at": started.isoformat() if started else "",
        "completed_at": (
            run_row.completed_at.isoformat() if run_row.completed_at else None
        ),
        "stages": _build_stages(run_row.state),
        "entities_discovered": entities_discovered,
        "entities_attributed": entities_attributed,
        "elapsed_seconds": elapsed_seconds,
    }

    return templates.TemplateResponse(
        request=request,
        name="partials/run_status.html",
        context={"run": run_dict},
    )
