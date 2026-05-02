# Production Deployment

This guide covers production deployment of Aevum with PostgreSQL,
`aevum-server`, Cedar policy, and optional OPA sidecar.

## Architecture overview

```
                   ┌──────────────────────────────────────────┐
                   │              Your infrastructure          │
                   │                                           │
  AI Agents ──────>│  reverse proxy (TLS)                     │
  MCP hosts ──────>│       │                                   │
  Your app  ──────>│  aevum-server (FastAPI)                   │
                   │       │                                   │
                   │  aevum-core                               │
                   │  ┌────┴────────────────────────────────┐  │
                   │  │ Cedar (in-process)                   │  │
                   │  │ OPA sidecar (optional, HTTP)         │  │
                   │  │ PostgreSQL (aevum-store-postgres)    │  │
                   │  └─────────────────────────────────────┘  │
                   └──────────────────────────────────────────┘
```

## Prerequisites

- Python 3.11+
- PostgreSQL 14+
- (Optional) OPA v0.60+

## Install

```bash
pip install aevum-core aevum-server aevum-store-postgres aevum-cli "aevum-core[cedar]"
```

## Database setup

```bash
# Create the database
createdb aevum

# Run migrations
aevum store migrate --dsn postgresql://user:password@host:5432/aevum
```

Or with the environment variable:

```bash
export AEVUM_DSN=postgresql://user:password@host:5432/aevum
aevum store migrate
```

## Configuring the Engine

```python
from aevum.core import Engine
from aevum.core.audit.sigchain import Sigchain
from aevum.store.postgres import PostgresGraphStore  # aevum-store-postgres

# Production: key from KMS
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
key = Ed25519PrivateKey.from_private_bytes(kms_client.get_secret("aevum-signing-key"))

engine = Engine(
    graph_store=PostgresGraphStore(dsn="postgresql://..."),
    sigchain=Sigchain(private_key=key, key_id="kms-key-2026-01"),
    opa_url="http://opa:8181",  # optional
)
```

## Running aevum-server

```bash
# Development
aevum server start --host 0.0.0.0 --port 8000

# Production (Gunicorn + Uvicorn workers)
gunicorn aevum.server.app:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000
```

## Docker Compose example

```yaml
version: "3.9"
services:
  aevum:
    image: python:3.11-slim
    command: >
      sh -c "pip install aevum-core aevum-server aevum-store-postgres 'aevum-core[cedar]' &&
             gunicorn aevum.server.app:app
             --workers 4
             --worker-class uvicorn.workers.UvicornWorker
             --bind 0.0.0.0:8000"
    environment:
      AEVUM_DSN: postgresql://aevum:secret@postgres:5432/aevum
      AEVUM_OPA_URL: http://opa:8181
    depends_on:
      - postgres
      - opa
    ports:
      - "8000:8000"

  postgres:
    image: postgres:16
    environment:
      POSTGRES_DB: aevum
      POSTGRES_USER: aevum
      POSTGRES_PASSWORD: secret
    volumes:
      - pgdata:/var/lib/postgresql/data

  opa:
    image: openpolicyagent/opa:latest
    command: run --server --addr :8181 /policies
    volumes:
      - ./policies:/policies

volumes:
  pgdata:
```

## Kubernetes (Helm) — coming soon

A Helm chart is planned for a future release. Until then, use the
Docker Compose reference architecture and adapt it to your Kubernetes setup.

## Scaling

`aevum-server` is stateless — scale horizontally with your load balancer.
All state is in PostgreSQL.

For high-throughput ingestion, use connection pooling (PgBouncer) in front
of PostgreSQL. Each Aevum operation makes 2-5 database calls.

## Monitoring

Aevum emits OpenTelemetry spans when a trace context is available.
Set the standard `OTEL_*` environment variables to route spans to your
observability backend.

Recommended alerts:

| Metric | Threshold | Meaning |
|---|---|---|
| `verify_sigchain()` failures | Any | Potential tampering |
| OPA latency p99 | > 500ms | OPA under load |
| `consent_required` rate | Spike | Misconfigured grants or attack |
| PostgreSQL connection errors | Any | DB unavailable |

## Backup and recovery

Back up three things:
1. **PostgreSQL database** — contains all three named graphs
2. **Ed25519 public key** — needed to verify the chain offline
3. **Consent grant records** — for GDPR right-to-erasure documentation

For point-in-time recovery, use PostgreSQL's WAL archiving.

## Upgrading

```bash
# Check current version
python -c "import aevum.core; print(aevum.core.__version__)"

# Upgrade
pip install --upgrade aevum-core aevum-server aevum-store-postgres aevum-cli

# Run migrations (new releases may add columns)
aevum store migrate --dsn postgresql://...
```

Always run `aevum store migrate` after upgrading. It is idempotent —
safe to run even if no migrations are needed.
