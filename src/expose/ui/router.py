"""FastAPI router serving the EXPOSE dashboard UI.

All routes return ``HTMLResponse`` rendered through Jinja2 templates.
HTMX partial endpoints live under ``/partials/`` and return HTML fragments
suitable for ``hx-swap``.

Static assets (CSS, JS) are mounted at ``/static/`` from the ``static/``
directory adjacent to this module.
"""

from __future__ import annotations

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


@router.get("/partials/entities", response_class=HTMLResponse)
async def entities_partial(request: Request, tenant_id: UUID) -> HTMLResponse:
    """Return the entity table partial for a given tenant.

    Called by HTMX on a 5-second poll cycle from the dashboard right pane.
    In the initial scaffold this returns placeholder data; the real
    implementation will query the entity repository once wired.
    """
    # Placeholder entities for initial template rendering.
    # Real implementation will use request.app.state.session_factory
    # to query EntityRepo for the given tenant.
    placeholder_entities = [
        {
            "id": "a1b2c3d4-0000-0000-0000-000000000001",
            "entity_type": "domain",
            "canonical_identifier": "example.com",
            "attribution_status": "confirmed",
            "first_observed_at": "2026-05-10T08:00:00Z",
            "last_observed_at": "2026-05-10T12:30:00Z",
        },
        {
            "id": "a1b2c3d4-0000-0000-0000-000000000002",
            "entity_type": "subdomain",
            "canonical_identifier": "api.example.com",
            "attribution_status": "high",
            "first_observed_at": "2026-05-10T08:15:00Z",
            "last_observed_at": "2026-05-10T12:30:00Z",
        },
        {
            "id": "a1b2c3d4-0000-0000-0000-000000000003",
            "entity_type": "ip",
            "canonical_identifier": "203.0.113.42",
            "attribution_status": "requires_review",
            "first_observed_at": "2026-05-10T09:00:00Z",
            "last_observed_at": "2026-05-10T12:30:00Z",
        },
        {
            "id": "a1b2c3d4-0000-0000-0000-000000000004",
            "entity_type": "subdomain",
            "canonical_identifier": "mail.example.com",
            "attribution_status": "medium",
            "first_observed_at": "2026-05-10T09:30:00Z",
            "last_observed_at": "2026-05-10T12:30:00Z",
        },
        {
            "id": "a1b2c3d4-0000-0000-0000-000000000005",
            "entity_type": "ip",
            "canonical_identifier": "198.51.100.7",
            "attribution_status": "confirmed",
            "first_observed_at": "2026-05-10T10:00:00Z",
            "last_observed_at": "2026-05-10T12:30:00Z",
        },
    ]

    return templates.TemplateResponse(
        request=request,
        name="partials/entity_table.html",
        context={"entities": placeholder_entities, "tenant_id": str(tenant_id)},
    )


@router.get("/partials/run-status/{run_id}", response_class=HTMLResponse)
async def run_status_partial(request: Request, run_id: UUID) -> HTMLResponse:
    """Return the run status bar partial.

    Called by HTMX on a 2-second poll cycle while a run is active.
    Displays pipeline stage progress (Seed -> Collect -> Sanitize ->
    Attribute -> Done).
    """
    # Placeholder run status for initial template rendering.
    # Real implementation will query RunRepo for the given run_id.
    placeholder_run = {
        "id": str(run_id),
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

    return templates.TemplateResponse(
        request=request,
        name="partials/run_status.html",
        context={"run": placeholder_run},
    )
