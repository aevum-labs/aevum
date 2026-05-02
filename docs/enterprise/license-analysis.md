# License Analysis

All Aevum packages are licensed under Apache-2.0.
The specification is licensed under CC-BY-4.0 + OWFa 1.0.1.

## Aevum packages

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

## Key dependencies

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

## psycopg2 / psycopg LGPL note

The PostgreSQL adapter (psycopg2 or psycopg3) is licensed under LGPL-3.
LGPL permits use in proprietary software without requiring you to open-source
your application, provided you:
1. Do not modify the LGPL library itself (using it via the standard API satisfies this)
2. Allow users to replace the LGPL library with a compatible version

Using `aevum-store-postgres` in a closed-source application is permitted
under standard LGPL-3 use terms.

If your legal policy prohibits LGPL dependencies, use `aevum-store-oxigraph`
(MIT / Apache-2.0) instead.

## Specification licenses

The Aevum protocol specification is dual-licensed:
- **CC-BY-4.0** — allows use, sharing, and adaptation with attribution
- **OWFa 1.0.1** (Open Web Foundation Agreement) — patent grant for implementors

The OWFa ensures that any patents covering the specification are freely licensed
to anyone who implements it. This is important for enterprise deployments that
cannot accept patent risk.

## Apache-2.0 obligations

Apache-2.0 requires:
1. Preserve the `LICENSE` file in distributions
2. Include the `NOTICE` file if one exists (Aevum currently has none)
3. State changes made to Apache-2.0 code (for modified distributions)

Using Aevum as a library (the typical case) has no attribution requirement
beyond preserving the license text.

## Complete dependency license audit

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
