---
description: "aevum-cli reference: all commands, options, and environment
variables for Aevum v0.7.1."
---

# CLI Reference

The `aevum` CLI provides server management, store operations, session
verification, receipt inspection, and conformance testing.

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
  aevum-core: 0.7.1
  aevum-server: 0.7.1
  aevum-store-oxigraph: 0.7.1
  aevum-store-postgres: 0.7.1
  aevum-mcp: 0.7.1
  aevum-cli: 0.7.1
```

---

## `aevum init`

Initialize the Aevum state directory and verify the signed principles file.

Creates the state directory, generates signing keys, and verifies `signed_principles.yaml`.

When `aevum-core[pqc]` is installed (liboqs available): generates Ed25519 + ML-DSA-65 hybrid
keys (the intended default per ADR-012). When liboqs is absent: generates Ed25519-only keys
and emits a loud warning — this is an interim degraded posture for v0.7.5; v0.8.0 will refuse
to start without the PQC backend (fail-closed, see [ADR-012](../adrs/adr-012-signing-posture.md)).

```bash
aevum init [OPTIONS]
```

**Options:**

| Option | Default | Description |
|---|---|---|
| `--state-dir, -s PATH` | `~/.aevum` | State directory path |
| `--principles, -p PATH` | `signed_principles.yaml` | Path to signed_principles.yaml |

**Example:**

```bash
aevum init --state-dir /var/lib/aevum
```

---

## `aevum verify`

Verify a session's Merkle root and signatures.

Re-reads the stored session events from SQLite, recomputes the Merkle root,
and compares it to the signed root in the sigchain. Exit 0 if valid, exit 1
if the root does not match (tampering detected).

```bash
aevum verify [OPTIONS] SESSION_ID
```

**Arguments:**

| Argument | Description |
|---|---|
| `SESSION_ID` | Session ID to verify |

**Options:**

| Option | Default | Description |
|---|---|---|
| `--state-dir, -s PATH` | `~/.aevum` | State directory path |

**Example:**

```bash
aevum verify sess_01HQMK7ZBN5X8Y4C6GRWAJ3KE5
```

---

## `aevum replay`

Replay a session and verify Merkle chain integrity.

Re-reads all events and recomputes the Merkle root. Reports any divergence
from the stored root, which indicates tampering. Unlike `verify`, `replay`
prints a step-by-step event trace when `--verbose` is set.

```bash
aevum replay [OPTIONS] SESSION_ID
```

**Arguments:**

| Argument | Description |
|---|---|
| `SESSION_ID` | Session ID to replay |

**Options:**

| Option | Default | Description |
|---|---|---|
| `--verbose, -v` | False | Show per-event results |
| `--state-dir, -s PATH` | `~/.aevum` | State directory path |

**Example:**

```bash
# Replay with full event trace
aevum replay --verbose sess_01HQMK7ZBN5X8Y4C6GRWAJ3KE5
```

---

## `aevum audit-pack`

Export an EU AI Act Article 12 audit pack for a session.

Produces a JSON-LD document using the PROV-O vocabulary, suitable for
regulatory disclosure or incident investigation under Article 12 of the
EU AI Act.

```bash
aevum audit-pack [OPTIONS] SESSION_ID
```

**Arguments:**

| Argument | Description |
|---|---|
| `SESSION_ID` | Session ID to export |

**Options:**

| Option | Default | Description |
|---|---|---|
| `--output, -o PATH` | stdout | Output file path |
| `--state-dir, -s PATH` | `~/.aevum` | State directory path |

**Example:**

```bash
# Write audit pack to file
aevum audit-pack sess_01HQMK7ZBN5X8Y4C6GRWAJ3KE5 -o audit-pack.json
```

---

## `aevum verify-receipt`

Verify an Aevum COSE_Sign1 receipt file or hash.

Decodes the receipt, verifies the Ed25519 signature over the canonical payload,
and prints a human-readable summary. Exit 0 on valid, exit 1 on invalid
signature, exit 2 on unsupported algorithm or hash not found.

```bash
aevum verify-receipt [OPTIONS] [RECEIPT_FILE]
```

**Arguments:**

| Argument | Description |
|---|---|
| `RECEIPT_FILE` | Path to COSE_Sign1 receipt file |

**Options:**

| Option | Description |
|---|---|
| `--hash TEXT` | SHA3-256 hex hash — lookup from `AEVUM_RECEIPT_DB` |

**Examples:**

```bash
# Verify a receipt file
aevum verify-receipt receipt.cbor

# Verify by hash (requires AEVUM_RECEIPT_DB)
aevum verify-receipt --hash a3f2b9c1...
```

---

## `aevum vault-check`

Verify Vault Transit connectivity with a sign/verify round-trip.

Reads `VAULT_ADDR`, `VAULT_TOKEN`, and `AEVUM_VAULT_KEY_NAME` from the
environment. Signs a test payload, then verifies the signature. Exit 0 on
success, exit 1 on configuration error or connectivity failure.

```bash
aevum vault-check
```

**Required environment variables:**

| Variable | Description |
|---|---|
| `VAULT_ADDR` | Vault server URL (e.g., `https://vault.example.com:8200`) |
| `VAULT_TOKEN` | Vault authentication token |
| `AEVUM_VAULT_KEY_NAME` | Transit key name (e.g., `aevum-signing-key`) |

**Example:**

```bash
export VAULT_ADDR=https://vault.example.com:8200
export VAULT_TOKEN=hvs.CAESIM...
export AEVUM_VAULT_KEY_NAME=aevum-signing-key
aevum vault-check
```

See [Deployment](/learn/deployment/#key-management) and
[docs/deployment/vault-setup.md](https://github.com/aevum-labs/aevum/blob/main/docs/deployment/vault-setup.md)
for the full Vault setup guide.

---

## `aevum conform`

Run the 9-invariant conformance suite.

Tests all required Aevum behavioral invariants and prints a report.
Exit 0 if all invariants pass, exit 1 if one or more fail.

```bash
aevum conform [OPTIONS]
```

**Options:**

| Option | Default | Description |
|---|---|---|
| `--output, -o TEXT` | `text` | Output format: `text` or `json` |

**Example:**

```bash
# Run conformance and save JSON report
aevum conform --output json > conform-report.json
```

---

## `aevum conformance run`

Run the Aevum conformance suite against the local installation.

```bash
aevum conformance run
```

Requires `aevum-conformance` to be installed.

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

Manage installed complications.

Subcommands: `list`, `install`, `approve`, `suspend`, `resume`.

```bash
aevum complication list
aevum complication install <name>
aevum complication approve <name>
aevum complication suspend <name>
aevum complication resume <name>
```

---

## Environment variables

| Variable | Description |
|---|---|
| `AEVUM_API_KEY` | API key for `aevum-server` |
| `AEVUM_DSN` | Default PostgreSQL DSN |
| `AEVUM_OPA_URL` | OPA sidecar URL (e.g., `http://opa:8181`) |
| `AEVUM_DEV` | Set to `1` for development mode (permissive, no persistence) |
| `AEVUM_RECEIPT_DB` | Path to receipt database for `verify-receipt --hash` |
| `VAULT_ADDR` | HashiCorp Vault server URL |
| `VAULT_TOKEN` | Vault authentication token |
| `AEVUM_VAULT_KEY_NAME` | Vault Transit key name |
| `AEVUM_REKOR_URL` | Rekor transparency log URL (default: from `AEVUM_REKOR_URL` env) |
| `AEVUM_TSA_URL` | RFC 3161 timestamp authority URL. If set, replaces the default TSA list (`timestamp.sigstore.dev`, `timestamp.digicert.com`) with a single entry. Useful for private or on-premises TSA deployments. |
