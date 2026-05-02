# Aevum

**The governed context kernel for AI agents.**

Aevum gives every AI agent cryptographic audit trails, human-review gates,
and consent-bound context assembly — built into the kernel, not bolted on.

!!! tip "Not sure if Aevum is right for your project?"
    Read the [fit assessment guide](guides/fit-assessment.md) first.
    It takes 5 minutes and gives you an honest answer.

[Get started in 10 minutes](getting-started/quickstart.md){ .md-button .md-button--primary }
[Is Aevum right for me?](guides/fit-assessment.md){ .md-button }

```python
from aevum.core import Engine
from aevum.core.consent.models import ConsentGrant

engine = Engine()
engine.add_consent_grant(ConsentGrant(
    grant_id="g1", subject_id="user-42", grantee_id="my-agent",
    operations=["ingest", "query"], purpose="customer-support",
    classification_max=1,
    granted_at="2026-01-01T00:00:00Z", expires_at="2027-01-01T00:00:00Z",
))

result = engine.ingest(
    data={"message": "User asked about billing"},
    provenance={"source_id": "support-chat", "chain_of_custody": ["support-chat"],
                "classification": 0},
    purpose="customer-support", subject_id="user-42", actor="my-agent",
)
print(result.audit_id)   # urn:aevum:audit:<uuid7>  -- cryptographically signed
print(result.status)     # ok
```

Every operation is signed, chained, and replayable. No consent grant = no operation.

## What Aevum provides

| Primitive | What it does |
|---|---|
| **Episodic ledger** | Ed25519-signed, SHA3-256-chained log of every AI decision |
| **Consent ledger** | OR-Set consent grants; revocation is immediate and propagates |
| **Five functions** | `ingest` `query` `review` `commit` `replay` — the governed API surface |
| **Human review gates** | Veto-as-default HITL gates with deadline enforcement |
| **Replay** | Deterministic reconstruction of any past decision |
| **Five absolute barriers** | Crisis detection, classification ceiling, consent, audit immutability, provenance — unconditional |
| **Complication framework** | Policy-governed complication system with 7-state lifecycle |
| **MCP integration** | All five functions available as tools for any MCP-compatible host |
| **Agent autonomy levels** | L1–L5 DeepMind taxonomy with automatic review triggers |

## Install

```bash
pip install aevum-core          # kernel only
pip install aevum-server        # + HTTP API
pip install "aevum-core[cedar]" # + real Cedar policy enforcement
```

## Architecture

```
┌─────────────────────────────────────┐
│           Your application          │
├──────────────┬──────────────────────┤
│  aevum-mcp   │  aevum-server        │  ← Entry points
│  (MCP tools) │  (HTTP API)          │
├──────────────┴──────────────────────┤
│            aevum-core               │  ← Kernel
│  ingest  query  review  commit  replay
│  ┌─────────────┐  ┌──────────────┐  │
│  │ Episodic    │  │ Consent      │  │
│  │ ledger      │  │ ledger       │  │
│  │ (sigchain)  │  │ (OR-Set)     │  │
│  └─────────────┘  └──────────────┘  │
│  ┌──────────────────────────────┐   │
│  │ Five absolute barriers       │   │
│  └──────────────────────────────┘   │
├─────────────────────────────────────┤
│  aevum-store-oxigraph / -postgres   │  ← Graph backends
└─────────────────────────────────────┘
```

## Packages

| Package | Purpose |
|---|---|
| `aevum-core` | Context kernel: five functions, sigchain, barriers, consent |
| `aevum-server` | HTTP API wrapping the five functions |
| `aevum-sdk` | Complication developer kit |
| `aevum-store-oxigraph` | Embedded RDF graph backend (single-node) |
| `aevum-store-postgres` | PostgreSQL graph + consent + ledger backend |
| `aevum-mcp` | MCP server for any MCP-compatible host (Claude Desktop, Cursor, and others) |
| `aevum-oidc` | OIDC token validation complication |
| `aevum-llm` | LiteLLM-backed LLM complication with audit trail |
| `aevum-cli` | `aevum server start`, `aevum store migrate`, and more |

## Community

- **Questions and discussion:** [GitHub Discussions](https://github.com/aevum-labs/aevum/discussions)
- **Bug reports:** [GitHub Issues](https://github.com/aevum-labs/aevum/issues)
- **Security vulnerabilities:** [GitHub Security Advisories](https://github.com/aevum-labs/aevum/security/advisories/new) (private)
- **Spec and conformance:** [aevum-labs/aevum-spec](https://github.com/aevum-labs/aevum-spec) and [aevum-labs/aevum-conformance](https://github.com/aevum-labs/aevum-conformance)

## License

Code: Apache-2.0  
Specification: CC-BY-4.0 + OWFa 1.0.1
