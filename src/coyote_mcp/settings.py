from uuid import UUID

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEVELOPMENT_SESSION_SECRET = "development-only-change-me"


def oidc_client_secret_reference(organization_id: UUID, provider_id: UUID) -> str:
    return f"env:COYOTE_OIDC_CLIENT_SECRET_{organization_id.hex.upper()}_{provider_id.hex.upper()}"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str = "postgresql+asyncpg://coyote:localdev-only@localhost:5432/coyote_mcp"
    allow_insecure_endpoints: bool = False
    allow_private_endpoints: bool = False
    allowed_insecure_endpoint_hosts: list[str] = []
    allowed_private_endpoint_hosts: list[str] = []
    discovery_timeout_seconds: float = 15.0
    execution_timeout_seconds: float = 15.0
    max_execution_result_bytes: int = 1_048_576
    pat_max_lifetime_seconds: int = 60 * 60 * 24 * 90
    default_organization_slug: str = "default"
    default_organization_display_name: str = "Default Organization"
    environment: str = "development"
    session_secret_key: str = "development-only-change-me"
    session_max_age_seconds: int = 60 * 60 * 8
    oidc_discovery_timeout_seconds: float = 10.0
    allow_insecure_oidc: bool = False
    allow_private_oidc: bool = False

    @model_validator(mode="after")
    def validate_session_secret(self) -> Settings:
        if not self.is_development and (
            self.session_secret_key == DEVELOPMENT_SESSION_SECRET
            or len(self.session_secret_key) < 32
        ):
            raise ValueError(
                "SESSION_SECRET_KEY must be externally configured with at least 32 characters "
                "outside development."
            )
        return self

    @property
    def is_development(self) -> bool:
        return self.environment == "development"

    @property
    def browser_session_cookie_name(self) -> str:
        return "coyote_session" if self.is_development else "__Host-coyote_session"

    @property
    def oidc_binding_cookie_name(self) -> str:
        return "coyote_oidc_binding" if self.is_development else "__Host-coyote_oidc_binding"
