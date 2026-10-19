FROM ghcr.io/astral-sh/uv:python3.14-bookworm-slim

WORKDIR /app

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

RUN groupadd --system coyote && useradd --system --gid coyote --home-dir /app coyote

COPY --chown=coyote:coyote pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project

COPY --chown=coyote:coyote src ./src
COPY --chown=coyote:coyote scripts ./scripts
COPY --chown=coyote:coyote alembic.ini ./
COPY --chown=coyote:coyote alembic ./alembic
RUN uv sync --frozen --no-dev

ENV PATH="/app/.venv/bin:$PATH"

USER coyote

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "from os import environ; from urllib.parse import urlsplit; from urllib.request import Request, urlopen; host = urlsplit(environ.get('COYOTE_PUBLIC_BASE_URL', 'http://127.0.0.1')).netloc; urlopen(Request('http://127.0.0.1:8000/healthz', headers={'Host': host}), timeout=3).read()"

CMD ["uvicorn", "coyote_mcp.app:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers"]
