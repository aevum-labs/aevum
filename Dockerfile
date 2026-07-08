# Build: 2026-06-02-force
# ── Stage 1: Build React / Vite frontend ─────────────────────────────────────
FROM node:20-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0 AS frontend-builder
WORKDIR /demo

COPY demo/package.json demo/package-lock.json ./
RUN npm ci

COPY demo/ ./

# Empty string = same-origin. React app and API run on the same server.
# All fetch("/v1/...") calls resolve to the current origin automatically.
ENV VITE_API_URL=""
RUN npm run build
# Output: /demo/dist/

# ── Stage 2: FastAPI server ───────────────────────────────────────────────────
FROM python:3.12-slim@sha256:423ed6ab25b1921a477529254bfeeabf5855151dc2c3141699a1bfc852199fbf AS app
WORKDIR /app

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy workspace files needed for aevum-maintainer
COPY pyproject.toml uv.lock ./
COPY packages/ packages/

# Install aevum-maintainer and its deps
RUN uv sync --frozen --no-dev --package aevum-maintainer

# Built React app served as static files
COPY --from=frontend-builder /demo/dist /app/static

EXPOSE 8080

CMD ["uv", "run", "--package", "aevum-maintainer", \
     "uvicorn", "aevum_maintainer.server:create_app", \
     "--factory", "--host", "0.0.0.0", "--port", "8080"]
