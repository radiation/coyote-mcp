"""Tenant-scoped, append-only persistence for security audit events."""

import asyncio
import json
import logging
import re
from collections.abc import Mapping
from enum import StrEnum
from uuid import UUID

from sqlalchemy import event
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from coyote_mcp.models import AuditEvent, Principal
from coyote_mcp.runtime import request_id
from coyote_mcp.settings import Settings

type AuditMetadataValue = str | int | bool

_MAX_METADATA_FIELDS = 8
_MAX_METADATA_BYTES = 1024
_MAX_METADATA_KEY_LENGTH = 64
_MAX_METADATA_STRING_LENGTH = 256
_SAFE_METADATA_STRING = re.compile(r"[A-Za-z0-9][A-Za-z0-9._,:-]{0,255}\Z")
logger = logging.getLogger(__name__)


class AuditActorType(StrEnum):
    HUMAN = "human"
    SERVICE = "service"
    SYSTEM = "system"


class AuditAction(StrEnum):
    ORGANIZATION_CREATED = "organization.created"
    SERVER_CREATED = "server.created"
    SERVER_UPDATED = "server.updated"
    SERVER_ENABLED = "server.enabled"
    SERVER_DISABLED = "server.disabled"
    SERVER_DELETED = "server.deleted"
    SERVER_SYNC = "server.sync"
    COLLECTION_CREATED = "collection.created"
    COLLECTION_UPDATED = "collection.updated"
    COLLECTION_ENABLED = "collection.enabled"
    COLLECTION_DISABLED = "collection.disabled"
    COLLECTION_MEMBERSHIP_ADDED = "collection.membership_added"
    COLLECTION_MEMBERSHIP_REMOVED = "collection.membership_removed"
    PUBLICATION_CREATED = "publication.created"
    PUBLICATION_UPDATED = "publication.updated"
    PUBLICATION_DELETED = "publication.deleted"
    CREDENTIAL_CREATED = "credential.created"
    CREDENTIAL_REVOKED = "credential.revoked"
    PRINCIPAL_CREATED = "principal.created"
    PRINCIPAL_DISABLED = "principal.disabled"
    GROUP_CREATED = "group.created"
    ROLE_MAPPING_CREATED = "role_mapping.created"
    CONNECTION_STARTED = "connection.started"
    CONNECTION_CONNECTED = "connection.connected"
    CONNECTION_DISCONNECTED = "connection.disconnected"
    POLICY_UPDATED = "policy.updated"
    AUTHENTICATION_FAILED = "authentication.failed"
    AUTHORIZATION_DENIED = "authorization.denied"
    MCP_EXECUTION = "mcp.execution"


class AuditTargetType(StrEnum):
    ORGANIZATION = "organization"
    PRINCIPAL = "principal"
    SERVER = "server"
    COLLECTION = "collection"
    PUBLICATION = "publication"
    CREDENTIAL = "credential"
    CONNECTION = "connection"
    POLICY = "policy"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    MCP_TOOL = "mcp_tool"


class AuditOutcome(StrEnum):
    SUCCESS = "success"
    DENIED = "denied"
    FAILURE = "failure"


class AuditMetadataValidationError(ValueError):
    """Raised when metadata cannot be safely persisted in an audit event."""


class AuditPersistenceError(RuntimeError):
    """Raised when an audit event cannot be durably flushed in the caller transaction."""


_METADATA_FIELDS: dict[AuditAction, frozenset[str]] = {
    AuditAction.ORGANIZATION_CREATED: frozenset({"organization_slug"}),
    AuditAction.SERVER_CREATED: frozenset({"server_name", "transport"}),
    AuditAction.SERVER_UPDATED: frozenset({"changed_fields"}),
    AuditAction.SERVER_ENABLED: frozenset(),
    AuditAction.SERVER_DISABLED: frozenset(),
    AuditAction.SERVER_DELETED: frozenset(),
    AuditAction.SERVER_SYNC: frozenset({"result_code", "tool_count"}),
    AuditAction.COLLECTION_CREATED: frozenset({"collection_slug", "exposure_mode"}),
    AuditAction.COLLECTION_UPDATED: frozenset({"changed_fields"}),
    AuditAction.COLLECTION_ENABLED: frozenset(),
    AuditAction.COLLECTION_DISABLED: frozenset(),
    AuditAction.COLLECTION_MEMBERSHIP_ADDED: frozenset({"server_id"}),
    AuditAction.COLLECTION_MEMBERSHIP_REMOVED: frozenset({"server_id"}),
    AuditAction.PUBLICATION_CREATED: frozenset({"published_name"}),
    AuditAction.PUBLICATION_UPDATED: frozenset({"changed_fields"}),
    AuditAction.PUBLICATION_DELETED: frozenset(),
    AuditAction.CREDENTIAL_CREATED: frozenset({"credential_kind", "key_version"}),
    AuditAction.CREDENTIAL_REVOKED: frozenset({"credential_kind"}),
    AuditAction.PRINCIPAL_CREATED: frozenset({"identity_type", "role_count"}),
    AuditAction.PRINCIPAL_DISABLED: frozenset({"identity_type"}),
    AuditAction.GROUP_CREATED: frozenset(),
    AuditAction.ROLE_MAPPING_CREATED: frozenset({"role", "scope"}),
    AuditAction.CONNECTION_STARTED: frozenset({"provider"}),
    AuditAction.CONNECTION_CONNECTED: frozenset({"provider"}),
    AuditAction.CONNECTION_DISCONNECTED: frozenset({"provider", "revocation_result"}),
    AuditAction.POLICY_UPDATED: frozenset({"changed_fields"}),
    AuditAction.AUTHENTICATION_FAILED: frozenset({"failure_code", "auth_method"}),
    AuditAction.AUTHORIZATION_DENIED: frozenset({"action", "reason_code"}),
    AuditAction.MCP_EXECUTION: frozenset({"execution_code", "duration_ms"}),
}


def _validated_metadata(
    action: AuditAction, metadata: Mapping[str, AuditMetadataValue] | None
) -> dict[str, AuditMetadataValue]:
    if metadata is None:
        return {}
    if not isinstance(metadata, Mapping):
        raise AuditMetadataValidationError("Audit metadata must be a mapping.")
    if len(metadata) > _MAX_METADATA_FIELDS:
        raise AuditMetadataValidationError("Audit metadata has too many fields.")

    allowed_fields = _METADATA_FIELDS[action]
    safe_metadata: dict[str, AuditMetadataValue] = {}
    for key, value in metadata.items():
        if not isinstance(key, str) or len(key) > _MAX_METADATA_KEY_LENGTH:
            raise AuditMetadataValidationError("Audit metadata contains an invalid field name.")
        if key not in allowed_fields:
            raise AuditMetadataValidationError("Audit metadata contains an unsupported field.")
        if isinstance(value, str):
            if (
                len(value) > _MAX_METADATA_STRING_LENGTH
                or _SAFE_METADATA_STRING.fullmatch(value) is None
            ):
                raise AuditMetadataValidationError("Audit metadata contains an oversized string.")
        elif not isinstance(value, (bool, int)):
            raise AuditMetadataValidationError("Audit metadata values must be scalar primitives.")
        safe_metadata[key] = value

    encoded = json.dumps(safe_metadata, separators=(",", ":"), ensure_ascii=True)
    if len(encoded.encode("utf-8")) > _MAX_METADATA_BYTES:
        raise AuditMetadataValidationError("Audit metadata exceeds the maximum size.")
    return safe_metadata


async def record_audit_event(
    session: AsyncSession,
    *,
    organization_id: UUID,
    actor_type: AuditActorType,
    actor_id: UUID | None,
    action: AuditAction,
    target_type: AuditTargetType,
    target_id: UUID | None,
    outcome: AuditOutcome,
    metadata: Mapping[str, AuditMetadataValue] | None = None,
    request_id_value: str | None = None,
) -> AuditEvent:
    """Add and flush an event in the caller-owned transaction without committing it."""
    if actor_type is AuditActorType.SYSTEM:
        if actor_id is not None:
            raise ValueError("System audit actors cannot have an actor ID.")
    elif actor_id is None:
        raise ValueError("Human and service audit actors require an actor ID.")

    audit_event = AuditEvent(
        organization_id=organization_id,
        actor_id=actor_id,
        actor_type=actor_type.value,
        action=action.value,
        target_type=target_type.value,
        target_id=target_id,
        outcome=outcome.value,
        request_id=request_id_value if request_id_value is not None else request_id(),
        metadata_=_validated_metadata(action, metadata),
    )
    session.add(audit_event)
    try:
        await session.flush()
    except SQLAlchemyError as error:
        raise AuditPersistenceError("Audit event persistence failed.") from error
    return audit_event


async def record_principal_audit_event(
    session: AsyncSession,
    *,
    organization_id: UUID,
    actor: Principal,
    action: AuditAction,
    target_type: AuditTargetType,
    target_id: UUID | None,
    metadata: Mapping[str, AuditMetadataValue] | None = None,
) -> AuditEvent:
    """Record a successful event initiated by a persisted principal."""
    return await record_audit_event(
        session,
        organization_id=organization_id,
        actor_type=(
            AuditActorType.SERVICE if actor.identity_type == "service" else AuditActorType.HUMAN
        ),
        actor_id=actor.id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        outcome=AuditOutcome.SUCCESS,
        metadata=metadata,
    )


async def record_independent_denial_event(
    session: AsyncSession,
    *,
    organization_id: UUID,
    action: AuditAction,
    target_type: AuditTargetType,
    metadata: Mapping[str, AuditMetadataValue],
    actor_type: AuditActorType = AuditActorType.SYSTEM,
    actor_id: UUID | None = None,
) -> None:
    """Persist a denied or failed security event outside the request transaction.

    This is intentionally best-effort: a failed audit write must not alter the
    authentication or authorization decision that prompted it.
    """
    if session.bind is None:
        logger.warning(
            "Independent audit event was not persisted action=%s reason=unbound_session",
            action.value,
        )
        return
    try:
        async with asyncio.timeout(Settings().independent_audit_timeout_seconds):
            async with AsyncSession(bind=session.bind, expire_on_commit=False) as audit_session:
                async with audit_session.begin():
                    await record_audit_event(
                        audit_session,
                        organization_id=organization_id,
                        actor_type=actor_type,
                        actor_id=actor_id,
                        action=action,
                        target_type=target_type,
                        target_id=None,
                        outcome=(
                            AuditOutcome.FAILURE
                            if action is AuditAction.AUTHENTICATION_FAILED
                            else AuditOutcome.DENIED
                        ),
                        metadata=metadata,
                    )
    except TimeoutError:
        logger.warning(
            "Independent audit event persistence timed out action=%s",
            action.value,
        )
    except (AuditMetadataValidationError, AuditPersistenceError, SQLAlchemyError) as error:
        logger.warning(
            "Independent audit event persistence failed action=%s exception_class=%s",
            action.value,
            type(error).__name__,
        )


def _reject_audit_event_mutation(*_: object) -> None:
    raise TypeError("Audit events are append-only.")


event.listen(AuditEvent, "before_update", _reject_audit_event_mutation)
event.listen(AuditEvent, "before_delete", _reject_audit_event_mutation)
