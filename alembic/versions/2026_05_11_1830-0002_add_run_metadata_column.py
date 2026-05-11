"""Add run_metadata JSONB column to runs table.

Revision ID: 0002
Revises: 0001
Create Date: 2026-05-11 18:30:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0002_add_run_metadata"
down_revision: Union[str, None] = "0001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "runs",
        sa.Column(
            "run_metadata",
            JSONB,
            nullable=False,
            server_default="'{}'::jsonb",
        ),
    )


def downgrade() -> None:
    op.drop_column("runs", "run_metadata")
