# Installation

All install options for Aevum. Start with the minimum and add what you need.

## Requirements

Python 3.11 or higher is required for all packages.

## Minimum install

```bash
pip install aevum-core
```

Includes: five functions, five absolute barriers, consent ledger, episodic ledger,
in-memory storage. No database required. Data does not persist across restarts.

## With persistence

```bash
# Embedded RDF, single-node, no database service required
pip install aevum-core aevum-store-oxigraph

# PostgreSQL — recommended for production
pip install aevum-core aevum-store-postgres
```

## With HTTP API

```bash
pip install aevum-server
```

FastAPI wrapper around the five functions. Exposes the same API over HTTP.

## With MCP tools

```bash
pip install aevum-mcp
```

All five functions as tools for any MCP-compatible host (Claude Desktop, Cursor,
VS Code Copilot, and others). See [MCP Setup](mcp-setup.md).

## With CLI

```bash
pip install aevum-cli
```

Adds `aevum server start`, `aevum store migrate`, and more.

## With Cedar policy enforcement

```bash
pip install "aevum-core[cedar]"
```

Adds real Cedar in-process policy evaluation. Recommended for production.

Without this extra, consent decisions fall back to permissive. The five absolute
barriers still fire unconditionally — crisis detection, classification ceiling,
consent (fast-path denials), audit immutability, and provenance are not affected
by whether Cedar is installed.

## Full production install

```bash
pip install aevum-core aevum-server aevum-store-postgres aevum-cli "aevum-core[cedar]"
```

## Virtual environments

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

## Verify installation

```bash
python -c "import aevum.core; print('aevum-core', aevum.core.__version__)"
```

## Platform notes

### ARM (Raspberry Pi, Apple Silicon)

`aevum-core` works on ARM32 and ARM64. The Ed25519 and SHA3-256 operations
used by the sigchain are fast on all modern ARM hardware.

For Apple Silicon (M1/M2/M3), install with:

```bash
pip install aevum-core
```

No special flags needed. The `cryptography` package ships universal wheels.

### Docker

```dockerfile
FROM python:3.11-slim
RUN pip install aevum-core
```

For production with persistence:

```dockerfile
FROM python:3.11-slim
RUN pip install aevum-core aevum-store-postgres aevum-server aevum-cli "aevum-core[cedar]"
```

### RHEL / Fedora

```bash
sudo dnf install python3.11 python3.11-pip
python3.11 -m venv .venv
source .venv/bin/activate
pip install aevum-core
```

## OPA sidecar (optional)

Aevum supports an OPA HTTP sidecar for infrastructure policy decisions.
It is optional — Cedar handles consent policy in-process.

If you use OPA, set the environment variable:

```bash
export AEVUM_OPA_URL=http://your-opa-host:8181
```

If OPA is configured but unreachable, Aevum fails closed (all operations denied).
