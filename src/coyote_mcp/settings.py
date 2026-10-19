import base64
import binascii
import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit

from pydantic import AliasChoices, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEVELOPMENT_SESSION_SECRET = "development-only-change-me"
DEVELOPMENT_DATABASE_URL = "postgresql+asyncpg://coyote:localdev-only@localhost:5432/coyote_mcp"
_CREDENTIAL_KEY_BYTES = 32


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
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", populate_by_name=True)
    database_url: str = DEVELOPMENT_DATABASE_URL
    public_base_url: str | None = Field(
        default=None,
        validation_alias=AliasChoices("COYOTE_PUBLIC_BASE_URL", "PUBLIC_BASE_URL"),
    )
    allowed_hosts: list[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("COYOTE_ALLOWED_HOSTS", "ALLOWED_HOSTS"),
    )
    trusted_proxy_networks: list[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("COYOTE_TRUSTED_PROXY_NETWORKS", "TRUSTED_PROXY_NETWORKS"),
    )
    oidc_enabled: bool = Field(
        default=True,
        validation_alias=AliasChoices("COYOTE_OIDC_ENABLED", "OIDC_ENABLED"),
    )
    downstream_credentials_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "COYOTE_DOWNSTREAM_CREDENTIALS_ENABLED", "DOWNSTREAM_CREDENTIALS_ENABLED"
        ),
    )
    downstream_oauth_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "COYOTE_DOWNSTREAM_OAUTH_ENABLED", "DOWNSTREAM_OAUTH_ENABLED"
        ),
    )
    allow_insecure_endpoints: bool = False
    allow_private_endpoints: bool = False
    allowed_insecure_endpoint_hosts: list[str] = []
    allowed_private_endpoint_hosts: list[str] = []
    discovery_timeout_seconds: float = 15.0
    execution_timeout_seconds: float = 15.0
    schema_validation_timeout_seconds: float = 5.0
    independent_audit_timeout_seconds: float = Field(
        default=2.0,
        gt=0,
        validation_alias=AliasChoices(
            "COYOTE_INDEPENDENT_AUDIT_TIMEOUT_SECONDS",
            "INDEPENDENT_AUDIT_TIMEOUT_SECONDS",
        ),
    )
    max_native_tools_per_collection: int = Field(
        default=100,
        ge=1,
        validation_alias=AliasChoices(
            "COYOTE_MAX_NATIVE_TOOLS_PER_COLLECTION", "MAX_NATIVE_TOOLS_PER_COLLECTION"
        ),
    )
    max_execution_result_bytes: int = 1_048_576
    pat_max_lifetime_seconds: int = 60 * 60 * 24 * 90
    credential_encryption_keys: dict[str, SecretStr] = Field(
        default_factory=dict,
        validation_alias=AliasChoices(
            "COYOTE_CREDENTIAL_ENCRYPTION_KEYS", "CREDENTIAL_ENCRYPTION_KEYS"
        ),
    )
    credential_active_key_version: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "COYOTE_CREDENTIAL_ACTIVE_KEY_VERSION", "CREDENTIAL_ACTIVE_KEY_VERSION"
        ),
    )
    downstream_oauth_redirect_base_url: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "COYOTE_DOWNSTREAM_OAUTH_REDIRECT_BASE_URL",
            "DOWNSTREAM_OAUTH_REDIRECT_BASE_URL",
        ),
    )
    downstream_oauth_timeout_seconds: float = Field(
        default=10.0,
        validation_alias=AliasChoices(
            "COYOTE_DOWNSTREAM_OAUTH_TIMEOUT_SECONDS",
            "DOWNSTREAM_OAUTH_TIMEOUT_SECONDS",
        ),
    )
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
    def validate_runtime_configuration(self) -> Settings:
        if not self.is_development and (
            self.session_secret_key == DEVELOPMENT_SESSION_SECRET
            or len(self.session_secret_key) < 32
        ):
            raise ValueError(
                "SESSION_SECRET_KEY must be externally configured with at least 32 characters "
                "outside development."
            )
        if self.is_development:
            return self
        self._validate_production_database_url()
        public_origin = self._validate_public_base_url()
        self._validate_allowed_hosts(public_origin)
        self._validate_trusted_proxy_networks()
        self._validate_safe_destination_configuration()
        self._validate_enabled_features(public_origin)
        return self

    def _validate_production_database_url(self) -> None:
        if (
            "database_url" not in self.model_fields_set
            or self.database_url == DEVELOPMENT_DATABASE_URL
        ):
            raise ValueError("DATABASE_URL must be explicitly configured outside development.")
        parsed = urlsplit(self.database_url)
        if parsed.scheme != "postgresql+asyncpg" or not parsed.hostname:
            raise ValueError("DATABASE_URL must use a PostgreSQL asyncpg URL outside development.")

    def _validate_public_base_url(self) -> str:
        if self.public_base_url is None:
            raise ValueError("PUBLIC_BASE_URL must be configured outside development.")
        parsed = urlsplit(self.public_base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("PUBLIC_BASE_URL must be an HTTPS origin outside development.")
        return f"https://{parsed.netloc}"

    def _validate_allowed_hosts(self, public_origin: str) -> None:
        if not self.allowed_hosts or "*" in self.allowed_hosts:
            raise ValueError(
                "ALLOWED_HOSTS must be an explicit non-wildcard list outside development."
            )
        public_host = urlsplit(public_origin).hostname
        if public_host is None or public_host not in self.allowed_hosts:
            raise ValueError("ALLOWED_HOSTS must include the PUBLIC_BASE_URL host.")
        for host in self.allowed_hosts:
            parsed = urlsplit(f"//{host}")
            if (
                not parsed.hostname
                or parsed.hostname != host
                or parsed.port is not None
                or parsed.username
                or parsed.password
                or parsed.path
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("ALLOWED_HOSTS entries must be hostnames without ports or paths.")

    def _validate_trusted_proxy_networks(self) -> None:
        if not self.trusted_proxy_networks:
            raise ValueError("TRUSTED_PROXY_NETWORKS must be configured outside development.")
        try:
            for network in self.trusted_proxy_networks:
                ipaddress.ip_network(network)
        except ValueError as error:
            raise ValueError(
                "TRUSTED_PROXY_NETWORKS must contain IP addresses or CIDRs."
            ) from error

    def _validate_safe_destination_configuration(self) -> None:
        if (
            self.allow_insecure_endpoints
            or self.allow_private_endpoints
            or self.allow_insecure_oidc
            or self.allow_private_oidc
            or self.allowed_insecure_endpoint_hosts
            or self.allowed_private_endpoint_hosts
        ):
            raise ValueError(
                "Development-only insecure or private endpoint settings are forbidden "
                "outside development."
            )

    def _validate_enabled_features(self, public_origin: str) -> None:
        if self.oidc_enabled:
            provider = self.oidc_provider()
            if self._origin(provider.redirect_uri) != public_origin:
                raise ValueError(
                    "OIDC_REDIRECT_URI must use the configured PUBLIC_BASE_URL origin."
                )
        credential_configuration_supplied = bool(
            self.credential_encryption_keys or self.credential_active_key_version
        )
        if credential_configuration_supplied and not self.downstream_credentials_enabled:
            raise ValueError(
                "Credential encryption configuration requires downstream credentials to be enabled."
            )
        if self.downstream_credentials_enabled:
            if not self.credential_encryption_keys or not self.credential_active_key_version:
                raise ValueError(
                    "Credential encryption keys and an active key version are required."
                )
            if self.credential_active_key_version not in self.credential_encryption_keys:
                raise ValueError("The active credential encryption key version is not configured.")
            for key in self.credential_encryption_keys.values():
                try:
                    decoded = base64.urlsafe_b64decode(key.get_secret_value())
                except (binascii.Error, ValueError) as error:
                    raise ValueError(
                        "Credential encryption key configuration is invalid."
                    ) from error
                if len(decoded) != _CREDENTIAL_KEY_BYTES:
                    raise ValueError("Credential encryption key configuration is invalid.")
        if self.downstream_oauth_redirect_base_url and not self.downstream_oauth_enabled:
            raise ValueError(
                "Downstream OAuth redirect configuration requires downstream OAuth to be enabled."
            )
        if self.downstream_oauth_enabled:
            if not self.downstream_credentials_enabled:
                raise ValueError("Downstream OAuth requires downstream credentials to be enabled.")
            if self.downstream_oauth_redirect_base_url is None:
                raise ValueError("Downstream OAuth requires a configured redirect base URL.")
            if self._origin(self.downstream_oauth_redirect_base_url) != public_origin:
                raise ValueError(
                    "Downstream OAuth redirect base URL must use the configured "
                    "PUBLIC_BASE_URL origin."
                )

    @staticmethod
    def _origin(url: str) -> str | None:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            return None
        return f"{parsed.scheme}://{parsed.netloc}"

    @property
    def is_development(self) -> bool:
        return self.environment == "development"

    @property
    def downstream_credentials_available(self) -> bool:
        return self.is_development or self.downstream_credentials_enabled

    @property
    def downstream_oauth_available(self) -> bool:
        return self.is_development or self.downstream_oauth_enabled

    @property
    def browser_session_cookie_name(self) -> str:
        return "coyote_session" if self.is_development else "__Host-coyote_session"

    @property
    def oidc_binding_cookie_name(self) -> str:
        return "coyote_oidc_binding" if self.is_development else "__Host-coyote_oidc_binding"

    @property
    def effective_allowed_hosts(self) -> tuple[str, ...]:
        return tuple(self.allowed_hosts) if self.allowed_hosts else ("*",)

    @property
    def public_origin(self) -> str | None:
        return self._origin(self.public_base_url) if self.public_base_url else None

    def oidc_provider(self) -> OIDCProviderConfiguration:
        if not self.oidc_enabled:
            raise ValueError("OIDC is disabled.")
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
