"""Harden registry migration backfills and synchronization."""

import hashlib
import json
from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def _fingerprint(tool: dict[str, Any]) -> str:
    metadata = {
        "annotations": tool["annotations"] or {},
        "description": tool["description"],
        "input_schema": tool["input_schema"] or {},
        "name": tool["name"],
        "output_schema": tool["output_schema"],
    }
    canonical = json.dumps(metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def upgrade() -> None:
    op.add_column(
        "servers",
        sa.Column("sync_generation", sa.Integer(), server_default=sa.text("0"), nullable=False),
    )
    connection = op.get_bind()
    tools = connection.execute(
        sa.text(
            """
            SELECT id, name, description, input_schema, output_schema, annotations
            FROM tools
            WHERE fingerprint = ''
            """
        )
    ).mappings()
    for tool in tools:
        connection.execute(
            sa.text("UPDATE tools SET fingerprint = :fingerprint WHERE id = :id"),
            {"fingerprint": _fingerprint(dict(tool)), "id": tool["id"]},
        )


def downgrade() -> None:
    op.drop_column("servers", "sync_generation")
