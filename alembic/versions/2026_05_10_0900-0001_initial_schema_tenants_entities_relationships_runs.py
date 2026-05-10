"""Initial schema: tenants, entities, relationships, runs.

Mirrors SPEC.md §5.4 illustrative DDL and the SQLAlchemy ORM models in
src/expose/db/models.py. Covers Sprint 1-2 acceptance for the data layer:
- tenants table with single-tenant default
- entities table with attribution status / confidence + indexes
- relationships table with provenance metadata + indexes
- runs table with state lifecycle

Per ADR-007 every relevant table has tenant_id NOT NULL with FK + ON DELETE
CASCADE so tenant deletion cleanly tears down associated rows. Per ADR-002
the schema is normalized graph; future Apache AGE migration is a parallel
access path on the same database.

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-05-10 09:00:00 UTC

"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial_schema"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ---- tenants ---------------------------------------------------------
    op.create_table(
        "tenants",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False, unique=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "config_jsonb",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )

    # Seed the v1 default tenant. Per ADR-007 §Decision: "v1 ships with a
    # single `default` tenant configured at deployment time." The fixed UUID
    # is reproducible across deployments — operators can override via env if
    # needed; lab dogfood relies on a stable id.
    op.execute(
        sa.text(
            "INSERT INTO tenants (id, name) VALUES "
            "('00000000-0000-0000-0000-000000000000', 'default')"
        )
    )

    # ---- entities --------------------------------------------------------
    op.create_table(
        "entities",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("entity_type", sa.String(64), nullable=False),
        sa.Column("canonical_identifier", sa.String(2048), nullable=False),
        sa.Column(
            "properties",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("attribution_status", sa.String(32), nullable=False),
        sa.Column(
            "attribution_confidence",
            sa.Numeric(precision=4, scale=3),
            nullable=False,
        ),
        sa.Column(
            "first_observed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "last_observed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "entity_type",
            "canonical_identifier",
            name="uq_entities_tenant_type_identifier",
        ),
    )
    op.create_index(
        "idx_entities_tenant_type", "entities", ["tenant_id", "entity_type"]
    )
    op.create_index(
        "idx_entities_canonical", "entities", ["tenant_id", "canonical_identifier"]
    )
    op.create_index(
        "idx_entities_attribution",
        "entities",
        ["tenant_id", "attribution_status", "attribution_confidence"],
    )

    # ---- relationships ---------------------------------------------------
    op.create_table(
        "relationships",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "from_entity_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("entities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "to_entity_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("entities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("edge_type", sa.String(64), nullable=False),
        sa.Column(
            "confidence", sa.Numeric(precision=4, scale=3), nullable=False
        ),
        sa.Column(
            "observed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column("collector_id", sa.String(128), nullable=False),
        sa.Column("evidence_ref", sa.String(128), nullable=True),
        sa.Column(
            "properties",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    op.create_index(
        "idx_relationships_from",
        "relationships",
        ["tenant_id", "from_entity_id", "edge_type"],
    )
    op.create_index(
        "idx_relationships_to",
        "relationships",
        ["tenant_id", "to_entity_id", "edge_type"],
    )
    op.create_index(
        "idx_relationships_observed_at",
        "relationships",
        ["tenant_id", "observed_at"],
    )

    # ---- runs ------------------------------------------------------------
    op.create_table(
        "runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("pipeline_version", sa.String(40), nullable=False),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "state", sa.String(32), nullable=False, server_default=sa.text("'pending'")
        ),
        sa.Column("canonical_artifact_ref", sa.String(256), nullable=True),
        sa.Column("manifest_ref", sa.String(256), nullable=True),
        sa.Column("target_count", sa.Integer(), nullable=True),
    )
    op.create_index("idx_runs_tenant_state", "runs", ["tenant_id", "state"])
    op.create_index(
        "idx_runs_tenant_started_at", "runs", ["tenant_id", "started_at"]
    )


def downgrade() -> None:
    # Strict reverse-dependency order: relationships → entities → runs → tenants.
    op.drop_index("idx_relationships_observed_at", table_name="relationships")
    op.drop_index("idx_relationships_to", table_name="relationships")
    op.drop_index("idx_relationships_from", table_name="relationships")
    op.drop_table("relationships")

    op.drop_index("idx_entities_attribution", table_name="entities")
    op.drop_index("idx_entities_canonical", table_name="entities")
    op.drop_index("idx_entities_tenant_type", table_name="entities")
    op.drop_table("entities")

    op.drop_index("idx_runs_tenant_started_at", table_name="runs")
    op.drop_index("idx_runs_tenant_state", table_name="runs")
    op.drop_table("runs")

    op.drop_table("tenants")
