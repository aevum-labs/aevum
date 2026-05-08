# Packages

Aevum is a monorepo. Each package is independently installable.

| Package | Purpose | Source |
|---|---|---|
| `aevum-core` | Context kernel: five functions, sigchain, barriers, consent | [source](https://github.com/aevum-labs/aevum/tree/main/packages/aevum-core) |
| `aevum-server` | HTTP API wrapping the five functions | [source](https://github.com/aevum-labs/aevum/tree/main/packages/aevum-server) |
| `aevum-sdk` | Complication developer kit | [source](https://github.com/aevum-labs/aevum/tree/main/packages/aevum-sdk) |
| `aevum-store-oxigraph` | Embedded RDF graph backend (single-node) | [source](https://github.com/aevum-labs/aevum/tree/main/packages/aevum-store-oxigraph) |
| `aevum-store-postgres` | PostgreSQL graph + consent + ledger backend | [source](https://github.com/aevum-labs/aevum/tree/main/packages/aevum-store-postgres) |
| `aevum-mcp` | MCP server for any MCP-compatible host | [source](https://github.com/aevum-labs/aevum/tree/main/packages/aevum-mcp) |
| `aevum-oidc` | OIDC token validation complication | [source](https://github.com/aevum-labs/aevum/tree/main/packages/aevum-oidc) |
| `aevum-llm` | LiteLLM-backed LLM complication with audit trail | [source](https://github.com/aevum-labs/aevum/tree/main/packages/aevum-llm) |
| `aevum-cli` | `aevum server start`, `aevum store migrate`, and more | [source](https://github.com/aevum-labs/aevum/tree/main/packages/aevum-cli) |
| `aevum-store-jena` | Apache Jena RDF backend (enterprise) | [source](https://github.com/aevum-labs/aevum/tree/main/packages/aevum-store-jena) |
| `aevum-spiffe` | SPIFFE/SPIRE agent identity complication | [source](https://github.com/aevum-labs/aevum/tree/main/packages/aevum-spiffe) |
| `aevum-publish` | Rekor v2 transparency log complication | [source](https://github.com/aevum-labs/aevum/tree/main/packages/aevum-publish) |

## Install

```bash
pip install aevum-core                    # kernel only
pip install aevum-server                  # + HTTP API
pip install "aevum-core[cedar]"           # + Cedar policy enforcement
pip install aevum-core aevum-store-postgres aevum-server aevum-cli "aevum-core[cedar]"  # production
```

See [Installation](../getting-started/installation.md) for the full guide.
