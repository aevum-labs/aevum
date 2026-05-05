---
description: "Install Aevum for production: backend options, PostgreSQL
setup, OIDC integration, and Apache-2.0 license analysis."
---

# Deployment

## Install options

All install options for Aevum. Start with the minimum and add what you need.

### Requirements

Python 3.11 or higher is required for all packages.

### Minimum install

```bash
pip install aevum-core
```

Includes: five functions, five absolute barriers, consent ledger, episodic ledger,
in-memory storage. No database required. Data does not persist across restarts.

### With persistence

```bash
# Embedded RDF, single-node, no database service required
pip install aevum-core aevum-store-oxigraph

# PostgreSQL — recommended for production
pip install aevum-core aevum-store-postgres
```

### With HTTP API

```bash
pip install aevum-server
```

FastAPI wrapper around the five functions. Exposes the same API over HTTP.

### With MCP tools

```bash
pip install aevum-mcp
```

All five functions as tools for any MCP-compatible host (Claude Desktop, Cursor,
VS Code Copilot, and others). See [MCP Setup](../getting-started/mcp-setup.md).

### With CLI

```bash
pip install aevum-cli
```

Adds `aevum server start`, `aevum store migrate`, and more.

### With Cedar policy enforcement

```bash
pip install "aevum-core[cedar]"
```

Adds real Cedar in-process policy evaluation. Recommended for production.

Without this extra, consent decisions fall back to permissive. The five absolute
barriers still fire unconditionally — crisis detection, classification ceiling,
consent (fast-path denials), audit immutability, and provenance are not affected
by whether Cedar is installed.

### Full production install

```bash
pip install aevum-core aevum-server aevum-store-postgres aevum-cli "aevum-core[cedar]"
```

### Virtual environments

Always install in a virtual environment:

=== "Linux / macOS"

    ```bash
    python -m venv .venv
    source .venv/bin/activate
    pip install aevum-core
    ```

=== "Windows (PowerShell)"

    ```powershell
    python -m venv .venv
    .venv\Scripts\Activate.ps1
    pip install aevum-core
    ```

=== "uv"

    ```bash
    uv add aevum-core
    ```

### Verify installation

```bash
python -c "import aevum.core; print('aevum-core', aevum.core.__version__)"
```

### Platform notes

#### ARM (Raspberry Pi, Apple Silicon)

`aevum-core` works on ARM32 and ARM64. The Ed25519 and SHA3-256 operations
used by the sigchain are fast on all modern ARM hardware.

For Apple Silicon (M1/M2/M3):

```bash
pip install aevum-core
```

No special flags needed. The `cryptography` package ships universal wheels.

#### Docker

```dockerfile
FROM python:3.11-slim
RUN pip install aevum-core
```

For production with persistence:

```dockerfile
FROM python:3.11-slim
RUN pip install aevum-core aevum-store-postgres aevum-server aevum-cli "aevum-core[cedar]"
```

#### RHEL / Fedora

```bash
sudo dnf install python3.11 python3.11-pip
python3.11 -m venv .venv
source .venv/bin/activate
pip install aevum-core
```

### OPA sidecar (optional)

Aevum supports an OPA HTTP sidecar for infrastructure policy decisions.
It is optional — Cedar handles consent policy in-process.

If you use OPA, set the environment variable:

```bash
export AEVUM_OPA_URL=http://your-opa-host:8181
```

If OPA is configured but unreachable, Aevum fails closed (all operations denied).

## Backend selection

| Backend | When to use |
|---|---|
| In-memory (default) | Development and testing — no database required |
| `aevum-store-oxigraph` | Single-node production — embedded RDF, no database service |
| `aevum-store-postgres` | Multi-node production — horizontal scaling, PITR |

**In-memory:** The default `Engine()`. No persistence — data is lost on restart.
Use for development, testing, and prototyping.

**Oxigraph:** Embedded RDF store. Data persists to disk. No database service
required. Good for single-node deployments, Raspberry Pi, and edge scenarios.

**PostgreSQL:** Recommended for production. Supports horizontal scaling,
connection pooling, point-in-time recovery, and standard database operations
(backups, monitoring, replication).

### Migration between backends

```bash
aevum store migrate --from oxigraph:/path --to postgres:postgresql://...
```

This migrates the knowledge graph, consent ledger, and episodic ledger.

## Production configuration

### Architecture overview

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

### Prerequisites

- Python 3.11+
- PostgreSQL 14+
- (Optional) OPA v0.60+

### Database setup

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

### Configuring the Engine

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

### Running aevum-server

```bash
# Development
aevum server start --host 0.0.0.0 --port 8000

# Production (Gunicorn + Uvicorn workers)
gunicorn aevum.server.app:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000
```

### Docker Compose example

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

### Scaling

`aevum-server` is stateless — scale horizontally with your load balancer.
All state is in PostgreSQL.

For high-throughput ingestion, use connection pooling (PgBouncer) in front
of PostgreSQL. Each Aevum operation makes 2-5 database calls.

### Monitoring

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

### Backup and recovery

Back up three things:
1. **PostgreSQL database** — contains all three named graphs
2. **Ed25519 public key** — needed to verify the chain offline
3. **Consent grant records** — for GDPR right-to-erasure documentation

For point-in-time recovery, use PostgreSQL's WAL archiving.

### Upgrading

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

### Kubernetes (Helm) — coming soon

A Helm chart is planned for a future release. Until then, use the
Docker Compose reference architecture and adapt it to your Kubernetes setup.

## OIDC and identity integration

Aevum does not implement authentication. Use `aevum-oidc` to validate JWTs
from your identity provider and map claims to `grantee_id` values:

```python
from aevum.oidc import OIDCComplication

oidc = OIDCComplication(jwks_uri="https://your-idp/.well-known/jwks.json")
engine.install_complication(oidc, auto_approve=True)

# After validation, use the verified subject as actor
actor = verified_token["sub"]  # e.g., "user:alice@example.com"
```

Common questions:

- *"How does it integrate with our existing identity provider?"*
  → via `aevum-oidc`. Your IDP issues the tokens; Aevum validates them.

- *"What are the data residency implications?"*
  → Aevum is self-hosted. Nothing leaves your infrastructure unless you configure
  an external OPA sidecar or OIDC endpoint.

## License

All Aevum packages are licensed under Apache-2.0.
The specification is licensed under CC-BY-4.0 + OWFa 1.0.1.

### Aevum packages

| Package | License | Notes |
|---|---|---|
| aevum-core | Apache-2.0 | Kernel, barriers, sigchain, consent |
| aevum-server | Apache-2.0 | FastAPI HTTP wrapper |
| aevum-sdk | Apache-2.0 | Complication developer kit |
| aevum-store-oxigraph | Apache-2.0 | Oxigraph graph backend |
| aevum-store-postgres | Apache-2.0 | PostgreSQL backend |
| aevum-mcp | Apache-2.0 | MCP server |
| aevum-oidc | Apache-2.0 | OIDC complication |
| aevum-llm | Apache-2.0 | LLM complication |
| aevum-cli | Apache-2.0 | CLI tool |

### Key dependencies

| Dependency | License | Used for |
|---|---|---|
| pydantic | MIT | Data validation (OutputEnvelope, ConsentGrant) |
| cryptography | Apache-2.0 / BSD | Ed25519 signing |
| fastapi | MIT | HTTP server (aevum-server) |
| uvicorn | BSD | ASGI server (aevum-server) |
| cedarpy | Apache-2.0 | Cedar policy evaluation (optional) |
| requests | Apache-2.0 | OPA HTTP client (optional) |
| click | BSD | CLI (aevum-cli) |
| oxigraph | MIT / Apache-2.0 | Graph storage (aevum-store-oxigraph) |
| psycopg2 / psycopg | LGPL-3 | PostgreSQL adapter (aevum-store-postgres) |

### psycopg2 / psycopg LGPL note

The PostgreSQL adapter (psycopg2 or psycopg3) is licensed under LGPL-3.
LGPL permits use in proprietary software without requiring you to open-source
your application, provided you:
1. Do not modify the LGPL library itself (using it via the standard API satisfies this)
2. Allow users to replace the LGPL library with a compatible version

Using `aevum-store-postgres` in a closed-source application is permitted
under standard LGPL-3 use terms.

If your legal policy prohibits LGPL dependencies, use `aevum-store-oxigraph`
(MIT / Apache-2.0) instead.

### Specification licenses

The Aevum protocol specification is dual-licensed:
- **CC-BY-4.0** — allows use, sharing, and adaptation with attribution
- **OWFa 1.0.1** (Open Web Foundation Agreement) — patent grant for implementors

The OWFa ensures that any patents covering the specification are freely licensed
to anyone who implements it. This is important for deployments that cannot accept
patent risk.

### Apache-2.0 obligations

Apache-2.0 requires:
1. Preserve the `LICENSE` file in distributions
2. Include the `NOTICE` file if one exists (Aevum currently has none)
3. State changes made to Apache-2.0 code (for modified distributions)

Using Aevum as a library (the typical case) has no attribution requirement
beyond preserving the license text.

### Complete dependency license audit

Run a full SBOM audit with:

```bash
pip install pip-licenses
pip-licenses --format=json --output-file=sbom.json
```

Or with uv:

```bash
uv add --dev pip-licenses
uv run pip-licenses --format=csv
```

This produces a complete software bill of materials for your security
and legal teams.

## See also

- [Quickstart](/getting-started/quickstart/) — local development setup
- [Security](/learn/security/) — security architecture for production
