from dataclasses import dataclass
from urllib.parse import urlsplit

from pydantic import AliasChoices, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEVELOPMENT_SESSION_SECRET = "development-only-change-me"


@dataclass(frozen=True)
class OIDCProviderConfiguration:
    issuer: str
    client_id: str
    client_secret: str
    redirect_uri: str
    allowed_organization: str | None
    group_claim: str | None
    trusted_endpoint_hosts: tuple[str, ...]
    jit_provisioning_enabled: bool


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str = "postgresql+asyncpg://coyote:localdev-only@localhost:5432/coyote_mcp"
    allow_insecure_endpoints: bool = False
    allow_private_endpoints: bool = False
    allowed_insecure_endpoint_hosts: list[str] = []
    allowed_private_endpoint_hosts: list[str] = []
    discovery_timeout_seconds: float = 15.0
    execution_timeout_seconds: float = 15.0
    schema_validation_timeout_seconds: float = 5.0
    max_native_tools_per_collection: int = Field(
        default=100,
        ge=1,
        validation_alias=AliasChoices(
            "COYOTE_MAX_NATIVE_TOOLS_PER_COLLECTION", "MAX_NATIVE_TOOLS_PER_COLLECTION"
        ),
    )
    max_execution_result_bytes: int = 1_048_576
    pat_max_lifetime_seconds: int = 60 * 60 * 24 * 90
    credential_encryption_keys: dict[str, SecretStr] = Field(default_factory=dict)
    credential_active_key_version: str | None = None
    downstream_oauth_redirect_base_url: str | None = None
    downstream_oauth_timeout_seconds: float = 10.0
    environment: str = "development"
    session_secret_key: str = "development-only-change-me"
    session_max_age_seconds: int = 60 * 60 * 8
    oidc_discovery_timeout_seconds: float = 10.0
    allow_insecure_oidc: bool = False
    allow_private_oidc: bool = False
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: SecretStr | None = None
    oidc_redirect_uri: str | None = None
    oidc_allowed_organization: str | None = None
    oidc_group_claim: str | None = None
    oidc_trusted_endpoint_hosts: list[str] = []
    oidc_jit_provisioning_enabled: bool = False

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

    def oidc_provider(self) -> OIDCProviderConfiguration:
        if any(
            value is None
            for value in (
                self.oidc_issuer,
                self.oidc_client_id,
                self.oidc_client_secret,
                self.oidc_redirect_uri,
            )
        ):
            raise ValueError(
                "OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, and "
                "OIDC_REDIRECT_URI are required."
            )
        assert self.oidc_issuer is not None
        assert self.oidc_client_id is not None
        assert self.oidc_client_secret is not None
        assert self.oidc_redirect_uri is not None
        issuer = self.oidc_issuer
        issuer_parts = urlsplit(issuer)
        redirect_uri = self.oidc_redirect_uri
        redirect_parts = urlsplit(redirect_uri)
        if (
            issuer_parts.scheme not in {"https", "http"}
            or not issuer_parts.netloc
            or issuer_parts.query
            or issuer_parts.fragment
            or redirect_parts.scheme not in {"https", "http"}
            or not redirect_parts.netloc
            or redirect_parts.path != "/auth/oidc/callback"
            or redirect_parts.query
            or redirect_parts.fragment
            or (
                not self.is_development
                and (issuer_parts.scheme != "https" or redirect_parts.scheme != "https")
            )
        ):
            raise ValueError("OIDC settings contain an invalid issuer or redirect URI.")
        return OIDCProviderConfiguration(
            issuer=issuer,
            client_id=self.oidc_client_id,
            client_secret=self.oidc_client_secret.get_secret_value(),
            redirect_uri=redirect_uri,
            allowed_organization=self.oidc_allowed_organization,
            group_claim=self.oidc_group_claim,
            trusted_endpoint_hosts=tuple(self.oidc_trusted_endpoint_hosts),
            jit_provisioning_enabled=self.oidc_jit_provisioning_enabled,
        )
