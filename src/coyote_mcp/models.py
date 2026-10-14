from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    String,
    UniqueConstraint,
    Uuid,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

JSONBType = JSON().with_variant(JSONB, "postgresql")


class Base(DeclarativeBase):
    pass


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    slug: Mapped[str] = mapped_column(String(160), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(160))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class MCPServer(Base):
    __tablename__ = "servers"
    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="uq_servers_organization_id_name"),
        UniqueConstraint("id", "organization_id", name="uq_servers_id_organization_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(160), index=True)
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
    __table_args__ = (
        UniqueConstraint("organization_id", "slug", name="uq_collections_organization_id_slug"),
        UniqueConstraint("id", "organization_id", name="uq_collections_id_organization_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    slug: Mapped[str] = mapped_column(String(160), index=True)
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
    __table_args__ = (
        Index("ix_collection_servers_server_id_enabled", "server_id", "enabled"),
        ForeignKeyConstraint(
            ["collection_id", "organization_id"],
            ["collections.id", "collections.organization_id"],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["server_id", "organization_id"],
            ["servers.id", "servers.organization_id"],
            ondelete="CASCADE",
        ),
    )

    collection_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    server_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    collection: Mapped[Collection] = relationship(back_populates="memberships")
    server: Mapped[MCPServer] = relationship(back_populates="memberships")


class Principal(Base):
    __tablename__ = "principals"
    __table_args__ = (
        UniqueConstraint("organization_id", "identifier", name="uq_principals_org_identifier"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    identifier: Mapped[str] = mapped_column(String(255))
    display_name: Mapped[str] = mapped_column(String(255))
    identity_type: Mapped[str] = mapped_column(String(32), default="human")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    credentials: Mapped[list[PersonalAccessToken]] = relationship(
        back_populates="principal", cascade="all, delete-orphan"
    )


class RoleAssignment(Base):
    __tablename__ = "role_assignments"
    __table_args__ = (
        UniqueConstraint(
            "principal_id",
            "role",
            "collection_id",
            name="uq_role_assignments_principal_role_collection",
        ),
        ForeignKeyConstraint(
            ["principal_id", "organization_id"],
            ["principals.id", "principals.organization_id"],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["collection_id", "organization_id"],
            ["collections.id", "collections.organization_id"],
            ondelete="CASCADE",
        ),
        CheckConstraint(
            "role IN ('owner', 'administrator', 'maintainer', 'consumer', 'viewer')",
            name="ck_role_assignments_role",
        ),
        Index(
            "uq_role_assignments_organization_scope",
            "principal_id",
            "role",
            unique=True,
            postgresql_where=text("collection_id IS NULL"),
            sqlite_where=text("collection_id IS NULL"),
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    principal_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False, index=True)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    collection_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class PersonalAccessToken(Base):
    __tablename__ = "personal_access_tokens"
    __table_args__ = (
        UniqueConstraint("token_id", name="uq_personal_access_tokens_token_id"),
        ForeignKeyConstraint(
            ["principal_id", "organization_id"],
            ["principals.id", "principals.organization_id"],
            ondelete="CASCADE",
        ),
        CheckConstraint("length(token_id) > 0", name="ck_personal_access_tokens_token_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    principal_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False, index=True)
    token_id: Mapped[str] = mapped_column(String(64), index=True)
    secret_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    scopes: Mapped[list[str]] = mapped_column(JSONBType, default=list)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    principal: Mapped[Principal] = relationship(back_populates="credentials")
