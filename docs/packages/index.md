# Packages

Aevum is a monorepo. Each package is independently installable.

| Package | Purpose | Status | Source |
|---|---|---|---|
| `aevum-core` | Context kernel: five functions, sigchain, barriers, consent | ✅ Available | [source](https://github.com/aevum-labs/aevum/tree/main/packages/aevum-core) |
| `aevum-server` | HTTP API wrapping the five functions | ✅ Available | [source](https://github.com/aevum-labs/aevum/tree/main/packages/aevum-server) |
| `aevum-store-oxigraph` | Embedded RDF graph backend (single-node) | ✅ Available | [source](https://github.com/aevum-labs/aevum/tree/main/packages/aevum-store-oxigraph) |
| `aevum-store-postgres` | PostgreSQL graph + consent + ledger backend | ✅ Available | [source](https://github.com/aevum-labs/aevum/tree/main/packages/aevum-store-postgres) |
| `aevum-mcp` | MCP server for any MCP-compatible host | ✅ Available | [source](https://github.com/aevum-labs/aevum/tree/main/packages/aevum-mcp) |
| `aevum-cli` | `aevum server start`, `aevum store migrate`, and more | ✅ Available | [source](https://github.com/aevum-labs/aevum/tree/main/packages/aevum-cli) |

## Install

| Install | Includes |
|---|---|
| `pip install aevum-core` | Kernel + NullPolicyEngine (permissive) + Oxigraph |
| `pip install "aevum-core[cedar]"` | + Cedar ABAC (recommended for production) |
| `pip install "aevum-core[all]"` | Everything |

```bash
pip install aevum-core                    # kernel only
pip install aevum-server                  # + HTTP API
pip install "aevum-core[cedar]"           # + Cedar policy enforcement
pip install aevum-core aevum-store-postgres aevum-server aevum-cli "aevum-core[cedar]"  # production
```

See [Deployment](../learn/deployment.md) for the full installation guide.
