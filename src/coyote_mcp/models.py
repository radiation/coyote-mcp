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
        back_populates="server",
        cascade="all, delete-orphan",
        passive_deletes=True,
        overlaps="collection,memberships",
    )


class Tool(Base):
    __tablename__ = "tools"
    __table_args__ = (
        UniqueConstraint("server_id", "name", name="uq_tools_server_id_name"),
        UniqueConstraint("id", "server_id", name="uq_tools_id_server_id"),
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
    exposure_mode: Mapped[str] = mapped_column(String(16), default="discovery", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    memberships: Mapped[list[CollectionMembership]] = relationship(
        back_populates="collection",
        cascade="all, delete-orphan",
        passive_deletes=True,
        overlaps="memberships,server",
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
    collection: Mapped[Collection] = relationship(
        back_populates="memberships", overlaps="memberships,server"
    )
    server: Mapped[MCPServer] = relationship(
        back_populates="memberships", overlaps="collection,memberships"
    )


class CollectionToolPublication(Base):
    __tablename__ = "collection_tool_publications"
    __table_args__ = (
        UniqueConstraint("collection_id", "tool_id", name="uq_collection_tool_publications_tool"),
        UniqueConstraint(
            "collection_id", "published_name", name="uq_collection_tool_publications_name"
        ),
        ForeignKeyConstraint(
            ["collection_id", "server_id"],
            ["collection_servers.collection_id", "collection_servers.server_id"],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tool_id", "server_id"],
            ["tools.id", "tools.server_id"],
            ondelete="CASCADE",
        ),
        Index("ix_collection_tool_publications_collection_enabled", "collection_id", "enabled"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    collection_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    server_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    tool_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    published_name: Mapped[str] = mapped_column(String(200), nullable=False)
    description_override: Mapped[str | None] = mapped_column(String(4096))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


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
    external_identities: Mapped[list[ExternalIdentity]] = relationship(
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


class BrowserSession(Base):
    __tablename__ = "browser_sessions"
    __table_args__ = (
        UniqueConstraint("token_id", name="uq_browser_sessions_token_id"),
        ForeignKeyConstraint(
            ["principal_id", "organization_id"],
            ["principals.id", "principals.organization_id"],
            ondelete="CASCADE",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    principal_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False, index=True)
    identity_provider_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), index=True)
    token_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    csrf_token_hash: Mapped[str | None] = mapped_column(String(128))
    verified_group_ids: Mapped[list[str]] = mapped_column(JSONBType, default=list)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    last_activity_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class OIDCLoginTransaction(Base):
    __tablename__ = "oidc_login_transactions"
    __table_args__ = (
        UniqueConstraint("state_hash", name="uq_oidc_login_transactions_state_hash"),
        ForeignKeyConstraint(
            ["provider_id", "organization_id"],
            ["identity_providers.id", "identity_providers.organization_id"],
            ondelete="CASCADE",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False, index=True)
    state_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    browser_binding_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    nonce: Mapped[str] = mapped_column(String(255), nullable=False)
    pkce_verifier: Mapped[str] = mapped_column(String(255), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class IdentityProvider(Base):
    __tablename__ = "identity_providers"
    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="uq_identity_providers_org_name"),
        UniqueConstraint("organization_id", "issuer", name="uq_identity_providers_org_issuer"),
        UniqueConstraint("id", "organization_id", name="uq_identity_providers_id_organization_id"),
        Index(
            "uq_identity_providers_one_active_org",
            "organization_id",
            unique=True,
            postgresql_where=text("enabled"),
            sqlite_where=text("enabled"),
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    issuer: Mapped[str] = mapped_column(String(2048), nullable=False)
    client_id: Mapped[str] = mapped_column(String(512), nullable=False)
    client_secret_reference: Mapped[str] = mapped_column(String(255), nullable=False)
    allowed_organization: Mapped[str | None] = mapped_column(String(255))
    group_claim: Mapped[str | None] = mapped_column(String(128))
    trusted_endpoint_hosts: Mapped[list[str]] = mapped_column(JSONBType, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    jit_provisioning_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ExternalIdentity(Base):
    __tablename__ = "external_identities"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "issuer", "subject", name="uq_external_identities_org_issuer_subject"
        ),
        ForeignKeyConstraint(
            ["principal_id", "organization_id"],
            ["principals.id", "principals.organization_id"],
            ondelete="CASCADE",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    principal_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False, index=True)
    issuer: Mapped[str] = mapped_column(String(2048), nullable=False)
    subject: Mapped[str] = mapped_column(String(1024), nullable=False)
    email: Mapped[str | None] = mapped_column(String(320))
    display_name: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    principal: Mapped[Principal] = relationship(back_populates="external_identities")


class ExternalGroup(Base):
    __tablename__ = "external_groups"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "identity_provider_id",
            "external_id",
            name="uq_external_groups_org_provider_external_id",
        ),
        UniqueConstraint("id", "organization_id", name="uq_external_groups_id_organization_id"),
        UniqueConstraint(
            "id",
            "organization_id",
            "identity_provider_id",
            name="uq_external_groups_id_org_provider",
        ),
        ForeignKeyConstraint(
            ["identity_provider_id", "organization_id"],
            ["identity_providers.id", "identity_providers.organization_id"],
            ondelete="CASCADE",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    identity_provider_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), index=True)
    external_id: Mapped[str] = mapped_column(String(512), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class GroupRoleMapping(Base):
    __tablename__ = "group_role_mappings"
    __table_args__ = (
        UniqueConstraint(
            "external_group_id", "role", "collection_id", name="uq_group_role_mapping_scope"
        ),
        ForeignKeyConstraint(
            ["external_group_id", "organization_id"],
            ["external_groups.id", "external_groups.organization_id"],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["collection_id", "organization_id"],
            ["collections.id", "collections.organization_id"],
            ondelete="CASCADE",
        ),
        CheckConstraint(
            "role IN ('owner', 'administrator', 'maintainer', 'consumer', 'viewer')",
            name="ck_group_role_mappings_role",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    external_group_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False, index=True)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    collection_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
