"""SQLAlchemy ORM models mirroring the schema in SPEC.md §5.4.

Per ADR-002: normalized graph schema. Per ADR-007: every relevant table carries
`tenant_id UUID NOT NULL` with foreign key to the `tenants` table; v1 ships with
a single `default` tenant configured at deployment time, but the schema is built
multi-tenant from day one.
"""
from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Index,
    Numeric,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
)


class Base(DeclarativeBase):
    """Base class for all ORM models.

    `JSONB` is used for properties columns on Postgres; on test databases (SQLite,
    if ever) SQLAlchemy will fall back to JSON.
    """

    # SQLAlchemy convention — class-level mapping is read once and not mutated.
    type_annotation_map = {  # noqa: RUF012
        dict[str, Any]: JSONB().with_variant(JSON(), "sqlite"),
    }


# Reusable column factory — TIMESTAMPTZ in Postgres, naive datetime elsewhere.
def _utc_now_column(*, default_factory_now: bool = True) -> Mapped[datetime]:
    return mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()") if default_factory_now else None,
    )


class Tenant(Base):
    """Tenant — the logical multi-tenancy boundary (per ADR-007).

    v1 ships with a single tenant named 'default'. Tenant lifecycle management
    (create / configure / suspend / delete) lands in the production-hardening
    epic; v1 has the schema but no admin API yet.
    """

    __tablename__ = "tenants"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    created_at: Mapped[datetime] = _utc_now_column()
    config_jsonb: Mapped[dict[str, Any]] = mapped_column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        server_default=text("'{}'::jsonb"),
    )

    entities: Mapped[list[Entity]] = relationship(
        back_populates="tenant",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    runs: Mapped[list[Run]] = relationship(
        back_populates="tenant",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class Entity(Base):
    """Observation graph node — Domain, Subdomain, IP, CIDR, Certificate,
    Service, CloudResource, Organization, Registrant, ASN per SPEC.md §5.2.
    """

    __tablename__ = "entities"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    canonical_identifier: Mapped[str] = mapped_column(String(2048), nullable=False)
    properties: Mapped[dict[str, Any]] = mapped_column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        server_default=text("'{}'::jsonb"),
    )
    attribution_status: Mapped[str] = mapped_column(String(32), nullable=False)
    attribution_confidence: Mapped[Decimal] = mapped_column(
        Numeric(precision=4, scale=3), nullable=False
    )
    first_observed_at: Mapped[datetime] = _utc_now_column()
    last_observed_at: Mapped[datetime] = _utc_now_column()

    tenant: Mapped[Tenant] = relationship(back_populates="entities")
    outgoing: Mapped[list[Relationship]] = relationship(
        back_populates="from_entity",
        foreign_keys="Relationship.from_entity_id",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    incoming: Mapped[list[Relationship]] = relationship(
        back_populates="to_entity",
        foreign_keys="Relationship.to_entity_id",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "entity_type",
            "canonical_identifier",
            name="uq_entities_tenant_type_identifier",
        ),
        Index("idx_entities_tenant_type", "tenant_id", "entity_type"),
        Index("idx_entities_canonical", "tenant_id", "canonical_identifier"),
        Index(
            "idx_entities_attribution",
            "tenant_id",
            "attribution_status",
            "attribution_confidence",
        ),
    )


class Relationship(Base):
    """Observation graph edge — typed, directional, with provenance metadata
    per SPEC.md §5.3."""

    __tablename__ = "relationships"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    from_entity_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    to_entity_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    edge_type: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[Decimal] = mapped_column(
        Numeric(precision=4, scale=3), nullable=False
    )
    observed_at: Mapped[datetime] = _utc_now_column()
    collector_id: Mapped[str] = mapped_column(String(128), nullable=False)
    evidence_ref: Mapped[str | None] = mapped_column(String(128), nullable=True)
    properties: Mapped[dict[str, Any]] = mapped_column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        server_default=text("'{}'::jsonb"),
    )

    from_entity: Mapped[Entity] = relationship(
        back_populates="outgoing", foreign_keys=[from_entity_id]
    )
    to_entity: Mapped[Entity] = relationship(
        back_populates="incoming", foreign_keys=[to_entity_id]
    )

    __table_args__ = (
        Index(
            "idx_relationships_from",
            "tenant_id",
            "from_entity_id",
            "edge_type",
        ),
        Index(
            "idx_relationships_to",
            "tenant_id",
            "to_entity_id",
            "edge_type",
        ),
        Index("idx_relationships_observed_at", "tenant_id", "observed_at"),
    )


class Run(Base):
    """A single pipeline run execution per SPEC.md §2.2 / §10.3.

    Carries metadata about the run lifecycle; the actual canonical artifact
    is stored in object storage (per ADR-004) and referenced via
    `canonical_artifact_ref` (sha256: pointer or URI).
    """

    __tablename__ = "runs"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    pipeline_version: Mapped[str] = mapped_column(String(40), nullable=False)
    started_at: Mapped[datetime] = _utc_now_column()
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    state: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default=text("'pending'")
    )
    canonical_artifact_ref: Mapped[str | None] = mapped_column(String(256), nullable=True)
    manifest_ref: Mapped[str | None] = mapped_column(String(256), nullable=True)
    target_count: Mapped[int | None] = mapped_column(nullable=True)

    tenant: Mapped[Tenant] = relationship(back_populates="runs")

    __table_args__ = (
        Index("idx_runs_tenant_state", "tenant_id", "state"),
        Index("idx_runs_tenant_started_at", "tenant_id", "started_at"),
    )
