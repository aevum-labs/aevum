FROM python:3.12-slim

WORKDIR /app

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy workspace files needed for aevum-maintainer
COPY pyproject.toml uv.lock ./
COPY packages/ packages/

# Install aevum-maintainer and its deps
RUN uv sync --frozen --no-dev --package aevum-maintainer

EXPOSE 8080

CMD ["uv", "run", "--package", "aevum-maintainer", \
     "uvicorn", "aevum_maintainer.server:create_app", \
     "--factory", "--host", "0.0.0.0", "--port", "8080"]
