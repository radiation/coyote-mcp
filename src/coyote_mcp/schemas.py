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
