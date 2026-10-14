from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

JSONBType = JSON().with_variant(JSONB, "postgresql")


class Base(DeclarativeBase):
    pass


class MCPServer(Base):
    __tablename__ = "servers"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(160), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(160))
    endpoint: Mapped[str] = mapped_column(String(2048))
    transport: Mapped[str] = mapped_column(String(32), default="streamable_http")
    status: Mapped[str] = mapped_column(String(32), default="pending")
    sync_generation: Mapped[int] = mapped_column(default=0)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_sync_error: Mapped[str | None] = mapped_column(String(2048))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    tools: Mapped[list[Tool]] = relationship(
        back_populates="server", cascade="all, delete-orphan", passive_deletes=True
    )
    memberships: Mapped[list[CollectionMembership]] = relationship(
        back_populates="server", cascade="all, delete-orphan", passive_deletes=True
    )


class Tool(Base):
    __tablename__ = "tools"
    __table_args__ = (
        UniqueConstraint("server_id", "name", name="uq_tools_server_id_name"),
        Index("ix_tools_server_id_active_name", "server_id", "active", "name"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    server_id: Mapped[UUID] = mapped_column(
        ForeignKey("servers.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(String(4096), default="")
    input_schema: Mapped[dict[str, Any]] = mapped_column(JSONBType, default=dict)
    output_schema: Mapped[dict[str, Any] | None] = mapped_column(JSONBType)
    annotations: Mapped[dict[str, Any]] = mapped_column(JSONBType, default=dict)
    fingerprint: Mapped[str] = mapped_column(String(64))
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    server: Mapped[MCPServer] = relationship(back_populates="tools")


class Collection(Base):
    __tablename__ = "collections"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    slug: Mapped[str] = mapped_column(String(160), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(String(1000), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    memberships: Mapped[list[CollectionMembership]] = relationship(
        back_populates="collection", cascade="all, delete-orphan", passive_deletes=True
    )


class CollectionMembership(Base):
    __tablename__ = "collection_servers"
    __table_args__ = (Index("ix_collection_servers_server_id_enabled", "server_id", "enabled"),)

    collection_id: Mapped[UUID] = mapped_column(
        ForeignKey("collections.id", ondelete="CASCADE"), primary_key=True
    )
    server_id: Mapped[UUID] = mapped_column(
        ForeignKey("servers.id", ondelete="CASCADE"), primary_key=True
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    collection: Mapped[Collection] = relationship(back_populates="memberships")
    server: Mapped[MCPServer] = relationship(back_populates="memberships")
