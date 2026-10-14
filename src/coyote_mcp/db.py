from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from coyote_mcp.settings import Settings


def get_engine(settings: Settings) -> AsyncEngine:
    return create_async_engine(settings.database_url, pool_pre_ping=True)
