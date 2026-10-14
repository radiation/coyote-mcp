from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str = "postgresql+asyncpg://coyote:localdev-only@localhost:5432/coyote_mcp"
    allow_insecure_endpoints: bool = False
    allow_private_endpoints: bool = False
    discovery_timeout_seconds: float = 15.0
