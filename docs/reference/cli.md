---
description: "aevum-cli reference: version, server start, store migrate, complication management, conformance run, and environment variable configuration."
---

# CLI Reference

The `aevum` CLI provides server management and store operations.

Install with:

```bash
pip install aevum-cli
```

On Windows, if `aevum` is not in your PATH:

```powershell
python -m aevum.cli --help
```

---

## `aevum version`

Print the installed version of all Aevum packages.

```bash
aevum version
```

Output:

```
Aevum package versions:
  aevum-core: 0.3.0
  aevum-server: 0.3.0
  aevum-sdk: 0.3.0
  ...
```

---

## `aevum server start`

Start the Aevum HTTP API server.

```bash
aevum server start [OPTIONS]
```

**Options:**

| Option | Default | Description |
|---|---|---|
| `--host TEXT` | `0.0.0.0` | Bind host |
| `--port INT` | `8000` | Bind port |
| `--workers INT` | `1` | Number of Uvicorn workers |
| `--graph TEXT` | `memory` | Graph backend (see below) |
| `--api-key TEXT` | None | API key (overrides `AEVUM_API_KEY` env var) |
| `--reload` | False | Enable auto-reload (development only) |

**Graph backend values:**

| Value | Description |
|---|---|
| `memory` | In-memory (dev only — data lost on restart) |
| `oxigraph:<path>` | Embedded Oxigraph at `<path>` |
| `postgres:<dsn>` | PostgreSQL at `<dsn>` |

**Examples:**

```bash
# Development (in-memory)
aevum server start

# With Oxigraph persistence
aevum server start --graph oxigraph:/var/lib/aevum/data

# With PostgreSQL
aevum server start --graph postgres:postgresql://user:pass@localhost:5432/aevum --workers 4

# With API key
aevum server start --api-key my-secret-key
# or
export AEVUM_API_KEY=my-secret-key
aevum server start
```

---

## `aevum store migrate`

Migrate graph data between backends.

```bash
aevum store migrate --from <source> --to <target>
```

**Options:**

| Option | Description |
|---|---|
| `--from TEXT` | Source backend (`oxigraph:<path>`) |
| `--to TEXT` | Target backend (`postgres:<dsn>`) |

Currently supported migration path: Oxigraph → PostgreSQL.

**Example:**

```bash
aevum store migrate \
  --from oxigraph:/var/lib/aevum/data \
  --to postgres:postgresql://user:pass@localhost:5432/aevum
```

---

## `aevum complication`

Manage installed complications (subcommands documented in a future release).

---

## `aevum conformance run`

Run the Aevum conformance suite against the local installation.

```bash
aevum conformance run
```

Requires `aevum-conformance` to be installed.

---

## Environment variables

| Variable | Description |
|---|---|
| `AEVUM_API_KEY` | API key for `aevum-server` |
| `AEVUM_DSN` | Default PostgreSQL DSN |
| `AEVUM_OPA_URL` | OPA sidecar URL (e.g., `http://opa:8181`) |
