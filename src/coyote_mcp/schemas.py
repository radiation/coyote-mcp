from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class Page(BaseModel):
    limit: int = Field(default=50, ge=1, le=100)
    offset: int = Field(default=0, ge=0)


class ServerCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160, pattern=r"^[a-z0-9][a-z0-9-]*$")
    display_name: str = Field(min_length=1, max_length=160)
    endpoint: HttpUrl
    transport: Literal["streamable_http"] = "streamable_http"


class ServerResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    display_name: str
    endpoint: str
    transport: str
    status: str
    last_synced_at: datetime | None
    last_sync_error: str | None
    created_at: datetime
    updated_at: datetime


class ToolResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    server_id: UUID
    name: str
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] | None
    annotations: dict[str, Any]
    fingerprint: str
    active: bool
    last_seen_at: datetime


class CollectionCreate(BaseModel):
    slug: str = Field(min_length=1, max_length=160, pattern=r"^[a-z0-9][a-z0-9-]*$")
    display_name: str = Field(min_length=1, max_length=160)
    description: str = Field(default="", max_length=1000)


class MembershipCreate(BaseModel):
    server_id: UUID
    enabled: bool = True


class MembershipResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    collection_id: UUID
    server_id: UUID
    enabled: bool


class CollectionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    slug: str
    display_name: str
    description: str
    enabled: bool
    created_at: datetime
    updated_at: datetime


class CollectionDetailResponse(CollectionResponse):
    memberships: list[MembershipResponse]


class PATCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    scopes: set[str] = Field(min_length=1)
    lifetime_seconds: int = Field(ge=1)


class PATResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    scopes: list[str]
    expires_at: datetime
    created_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None


class PATCreatedResponse(PATResponse):
    token: str


class ServicePrincipalCreate(BaseModel):
    identifier: str = Field(min_length=1, max_length=255, pattern=r"^[a-z0-9][a-z0-9-]*$")
    display_name: str = Field(min_length=1, max_length=255)
    roles: set[Literal["owner", "administrator", "maintainer", "consumer", "viewer"]] = Field(
        default_factory=set
    )


class PrincipalResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    identifier: str
    display_name: str
    identity_type: str
    enabled: bool
    created_at: datetime


class ServicePATCreate(PATCreate):
    pass


class IdentityProviderCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    issuer: HttpUrl
    client_id: str = Field(min_length=1, max_length=512)
    client_secret_reference: str = Field(min_length=5, max_length=255, pattern=r"^env:[A-Z0-9_]+$")
    allowed_organization: str | None = Field(default=None, max_length=255)
    group_claim: str | None = Field(default=None, max_length=128)
    trusted_endpoint_hosts: list[str] = Field(default_factory=list, max_length=20)
    jit_provisioning_enabled: bool = False


class ExternalGroupCreate(BaseModel):
    identity_provider_id: UUID
    external_id: str = Field(min_length=1, max_length=512)
    display_name: str = Field(min_length=1, max_length=255)


class GroupRoleMappingCreate(BaseModel):
    role: Literal["owner", "administrator", "maintainer", "consumer", "viewer"]
    collection_id: UUID | None = None
