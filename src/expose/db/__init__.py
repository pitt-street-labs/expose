"""Database layer for EXPOSE Core.

Per ADR-002: Postgres with normalized graph schema. Entities and relationships
are stored as tables with `tenant_id` columns enforcing logical multi-tenancy
(per ADR-007). Recursive CTEs handle traversal queries.

Sprint 1-2 lands the schema and Alembic v0001 migration. Sprint 3+ adds the
tenant-scoped query helpers that middleware uses to inject tenant context into
every database call.
"""
from expose.db.engine import (
    DatabaseSettings,
    create_async_engine_from_settings,
    create_session_factory,
)
from expose.db.models import (
    Base,
    Entity,
    Relationship,
    Run,
    Tenant,
)

__all__ = [
    "Base",
    "DatabaseSettings",
    "Entity",
    "Relationship",
    "Run",
    "Tenant",
    "create_async_engine_from_settings",
    "create_session_factory",
]
