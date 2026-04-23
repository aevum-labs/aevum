# Aevum — Claude Code Reference

This is the briefing document for Claude Code sessions working on the
`aevum-labs/aevum` monorepo. Read it fully before writing any code.

For the complete design rationale and phase plan, see the Aevum planning
conversation (Claude.ai project).

---

## What Aevum Is

Aevum is a replay-first, policy-governed context kernel. It sits between raw
data sources and AI consumers. It ingests data through a governed membrane,
records canonical truth in an append-only episodic ledger, assembles bounded
context through graph traversal, and enables deterministic replay of any past
decision.

It is NOT: a data integration platform, an AI orchestration framework, a
compliance report generator, a knowledge graph database, an agent execution
environment, a streaming broker, or an observability backend.
See NON-GOALS.md for the full normative list.

---

## Current State

Phase 0 is complete (namespaces, governance, monorepo skeleton).
Phase 1 (protocol specification) is next.

Do not implement logic not yet designed. If something is not in this
document and not in a phase briefing, ask rather than infer.

---

## GitHub and PyPI

- GitHub: aevum-labs (personal account, also serves as the org)
- Main monorepo: github.com/aevum-labs/aevum
- Spec repo: github.com/aevum-labs/aevum-spec
- Conformance repo: github.com/aevum-labs/aevum-conformance
- Domains repo: github.com/aevum-labs/aevum-domains
- Primary PyPI package: aevum-core
- Project domain: aevum.dev

---

## The Five Public Functions (STABLE — DO NOT CHANGE)

These are the complete public API of aevum-core. Their signatures and
behavioral contracts are frozen at Phase 1.

| Function | Internal name | Verb |
|---|---|---|
| ingest  | RELATE   | Write data through the governed membrane |
| query   | NAVIGATE | Traverse the graph for a declared purpose |
| review  | GOVERN   | Present context for human decision |
| commit  | REMEMBER | Append event to the episodic ledger |
| replay  | (new)    | Reconstruct any past decision faithfully |

Never use: checkpoint (use review), explain (use replay),
navigate (use query), write/insert/store (use ingest).

---

## Package Structure

| PyPI name            | Import path          | Role                      |
|---|---|---|
| aevum-core           | aevum.core           | The kernel                |
| aevum-sdk            | aevum.sdk            | Complication dev kit      |
| aevum-store-oxigraph | aevum.store.oxigraph | Small deployments         |
| aevum-store-postgres | aevum.store.postgres | Team deployments          |
| aevum-store-jena     | aevum.store.jena     | Enterprise deployments    |
| aevum-mcp            | aevum.mcp            | MCP server complication   |
| aevum-llm            | aevum.llm            | LLM adapter complication  |
| aevum-oidc           | aevum.oidc           | OIDC federation           |
| aevum-cli            | aevum.cli            | Command-line interface    |

---

## Namespace Package Rule — CRITICAL

`aevum` is a native namespace package (PEP 420).

NEVER create __init__.py in:
  packages/*/src/aevum/
  packages/*/src/aevum/store/
  packages/*/src/aevum/domain/

ALWAYS create __init__.py in the actual leaf package:
  packages/aevum-core/src/aevum/core/__init__.py
  packages/aevum-store-oxigraph/src/aevum/store/oxigraph/__init__.py

Run `python scripts/check_namespace.py` to verify. Exits 1 on violation.

---

## Terminology — Always / Never

| Use                            | Never use                              |
|---|---|
| complication                   | plugin, extension, module, addon       |
| episodic ledger                | audit log, audit trail, event log      |
| governed membrane              | gateway, filter, middleware            |
| review (function)              | checkpoint, approve, authorize         |
| replay (function)              | explain, audit, reconstruct            |
| ingest (function)              | write, insert, store, index            |
| query (function)               | search, fetch, retrieve, navigate      |
| commit (function)              | save, persist, log, record             |
| canonical truth                | source of truth (ledger concept only)  |
| standard relationship vocabulary | canonical vocabulary                 |
| absolute barrier               | policy rule, circuit breaker           |
| sigchain                       | signed chain, audit chain, hash chain  |

---

## Frozen Invariants (Cannot Change After Phase 1)

1. The four function verbs: ingest=RELATE, query=NAVIGATE, review=GOVERN, commit=REMEMBER
2. The replay function signature and guarantee
3. All OutputEnvelope mandatory fields
4. The absolute barriers (hardcoded in barriers.py — NOT policy)
5. The append-only property of the episodic ledger
6. Consent as precondition (no traversal without consent)
7. Provenance as precondition (no ingestion without chain of custody)
8. Apache-2.0 license for all code
9. CC-BY-4.0 + OWFa 1.0.1 for the spec
10. Three Named Graph URIs:
      urn:aevum:knowledge   (working graph)
      urn:aevum:provenance  (immutable audit)
      urn:aevum:consent     (consent ledger)

---

## Build System

Each package uses hatchling with packages set to the src/aevum subtree for
namespace support:

    [build-system]
    requires = ["hatchling"]
    build-backend = "hatchling.build"

    [tool.hatch.build.targets.wheel]
    packages = ["src/aevum"]

uv_build (0.11.7, bundled with uv 0.8.x) does not support dotted module-name
paths for namespace packages — it resolves them as flat underscore-separated
names. hatchling correctly preserves the directory hierarchy (src/aevum/core →
aevum/core in the wheel) without injecting __init__.py into the namespace root.

The root pyproject.toml is a virtual workspace (no [project] section).
Never publish the root. Only publish individual packages under packages/.

---

## Policy Architecture

Hybrid OPA + Cedar:
- Cedar (cedarpy, in-process): consent and purpose decisions
- OPA (sidecar, HTTP): infrastructure policy
- Absolute barriers (barriers.py): hardcoded, not policy, not configurable
