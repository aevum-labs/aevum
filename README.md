# Aevum

**The governed context kernel for AI agents.**

Aevum gives every AI agent cryptographic audit trails, human-review gates,
and consent-bound context assembly -- built into the kernel, not bolted on.

Aevum is a context kernel in the microkernel sense: a minimal, stable
enforcement primitive (consent, provenance, sigchain, deterministic
replay) combined with externalized policy (Cedar, OPA). The five absolute
barriers stay stable as regulations evolve — the Cedar/OPA policy bundles
change with them. See
[Standards and Regulatory Alignment](https://aevum.build/learn/standards-alignment/)
for the regulatory mapping.

Documentation: https://aevum.build

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12630/badge)](https://www.bestpractices.dev/projects/12630)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/aevum-core.svg)](https://pypi.org/project/aevum-core/)

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
| **Five functions** | `ingest` `query` `review` `commit` `replay` -- the governed API surface |
| **Human review gates** | Veto-as-default HITL gates with deadline enforcement |
| **Replay** | Deterministic reconstruction of any past decision |
| **Five absolute barriers** | Crisis detection, classification ceiling, consent, audit immutability, provenance -- unconditional |
| **Complication framework** | Policy-governed plugin system with 7-state lifecycle |
| **MCP integration** | All five functions available as tools for any MCP-compatible host |
| **Agent autonomy levels** | L1-L5 DeepMind taxonomy with automatic review triggers |

## Install

```bash
pip install aevum-core          # kernel only
pip install aevum-server        # + HTTP API
pip install "aevum-core[cedar]" # + real Cedar policy enforcement
```

## 10-minute quickstart

```bash
pip install aevum-core

python - << 'EOF'
from aevum.core import Engine
from aevum.core.consent.models import ConsentGrant

engine = Engine()

# Grant consent for an agent to ingest and query data about a user
engine.add_consent_grant(ConsentGrant(
    grant_id="demo-grant",
    subject_id="user-1",
    grantee_id="demo-agent",
    operations=["ingest", "query"],
    purpose="product-demo",
    classification_max=0,
    granted_at="2026-01-01T00:00:00Z",
    expires_at="2030-01-01T00:00:00Z",
))

# Ingest data -- every write is signed and chained
result = engine.ingest(
    data={"note": "User requested account review"},
    provenance={"source_id": "demo", "chain_of_custody": ["demo"], "classification": 0},
    purpose="product-demo",
    subject_id="user-1",
    actor="demo-agent",
)
print("audit_id:", result.audit_id)  # urn:aevum:audit:<uuid7>
print("status:  ", result.status)    # ok

# Query -- no consent grant = no results (Barrier 3)
q = engine.query(purpose="product-demo", subject_ids=["user-1"], actor="demo-agent")
print("results: ", list(q.data["results"].keys()))  # ['user-1']

# Replay any past decision deterministically
r = engine.replay(audit_id=result.audit_id, actor="demo-agent")
print("replayed:", r.data["replayed_payload"]["note"])  # User requested account review
EOF
```

## What Aevum is not

- **Not a prompt injection defense** — use a guardrail layer (Lakera Guard,
  NeMo Guardrails) on the model boundary
- **Not a code execution sandbox** — use gVisor, Firecracker, or NVIDIA
  OpenShell for process isolation
- **Not a mandatory network enforcement point** — deploy behind an AI gateway
  or MCP gateway for that; see
  [Deployment Patterns](https://aevum.build/learn/deployment-patterns/)
- **Not a compliance report generator** — the episodic ledger produces
  evidence; your compliance program interprets it

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

## Documentation

- [Architecture](https://aevum.build/learn/architecture/)
- [Quickstart](https://aevum.build/getting-started/quickstart/)
- [Deployment Patterns](https://aevum.build/learn/deployment-patterns/)
- [Standards Alignment](https://aevum.build/learn/standards-alignment/)
- [Full documentation](https://aevum.build)

## Community

- **Questions and discussion:** [GitHub Discussions](https://github.com/aevum-labs/aevum/discussions)
- **Bug reports:** [GitHub Issues](https://github.com/aevum-labs/aevum/issues)
- **Security vulnerabilities:** [GitHub Security Advisories](https://github.com/aevum-labs/aevum/security/advisories/new) (private)
- **Spec and conformance:** [aevum-labs/aevum-spec](https://github.com/aevum-labs/aevum-spec) and [aevum-labs/aevum-conformance](https://github.com/aevum-labs/aevum-conformance)

## License

Code: Apache-2.0
Specification: CC-BY-4.0 + OWFa 1.0.1
