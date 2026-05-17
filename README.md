# Aevum

Governed context kernel for AI agents. Signed audit trail, consent-gated data
access, and verifiable decision records — three controls that regulators ask for
together and that are hardest to add after the fact.

[![CI](https://github.com/aevum-labs/aevum/actions/workflows/ci.yml/badge.svg)](https://github.com/aevum-labs/aevum/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/aevum-core)](https://pypi.org/project/aevum-core/)
[![Python](https://img.shields.io/pypi/pyversions/aevum-core)](https://pypi.org/project/aevum-core/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

**Live demo:** [demo.aevum.build](https://demo.aevum.build) — see the governed
maintenance pipeline in action, with a live sigchain, interactive sandbox,
and Article 12 compliance reports.

## The problem

AI agents are uniquely exposed to the **lethal trifecta**: reading untrusted
content, accessing private user data, and exfiltrating via a tool call — three
steps that are innocuous individually but catastrophic in composition. Aevum's
Cedar policies block that composition unconditionally, before any permit can
override it.

Beyond trifecta prevention, every AI system operating on personal data needs
three things the standard stack does not provide:

1. **A signed, replayable record** of every decision (EU AI Act Article 12,
   HIPAA §164.312)
2. **Consent as a precondition** for any data traversal (GDPR Art. 6/9)
3. **Crypto-erasure** when a subject exercises the right to be forgotten
   (GDPR Art. 17)

Aevum makes all three structural rather than procedural.

## Quick demo

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
print(result.audit_id)   # urn:aevum:audit:<uuid7>  — signed, chained, replayable
print(result.status)     # ok
```

No consent grant? `result.status == "error"` with `error_code == "consent_required"`.
Crisis keyword in data? Blocked before the graph write. No exceptions.

## LangGraph drop-in

```python
from aevum.core.adapters.langgraph import AevumCheckpointer
checkpointer = AevumCheckpointer.local()
graph = builder.compile(checkpointer=checkpointer)
```

Every superstep is dual-signed (Ed25519 + ML-DSA-65) and chained.
`delete_thread(thread_id)` triggers GDPR Art. 17 crypto-erasure.

## Install

```bash
pip install aevum-core                     # kernel only
pip install "aevum-core[server]"           # + HTTP API
pip install "aevum-core[langgraph]"        # + LangGraph checkpointer
pip install "aevum-core[oxigraph]"         # + embedded RDF graph
pip install "aevum-core[postgres]"         # + PostgreSQL backend
pip install "aevum-core[mcp]"             # + MCP integration
pip install "aevum-core[all]"              # everything
```

> **Note:** The bare name `aevum` on PyPI is an unrelated project.
> Always use `aevum-core` (or another `aevum-*` package).

## The five functions (CRE protocol)

| Function | Protocol verb | What it does |
|---|---|---|
| `ingest` | RELATE | Write data through the governed membrane |
| `query` | NAVIGATE | Traverse the graph for a declared purpose |
| `review` | GOVERN | Present context for human decision |
| `commit` | REMEMBER | Append event to the episodic ledger |
| `replay` | (no verb) | Reconstruct any past decision faithfully |

All five are consent-checked, barrier-enforced, and ledger-recorded.

## The five absolute barriers

These are Cedar `forbid` policies. Cedar semantics: forbid always overrides
permit. No configuration, no override, no escape hatch.

| Barrier | What it blocks |
|---|---|
| **1 — Crisis** | Any graph write when crisis-signal keywords are detected |
| **2 — Consent** | Any context traversal without a scoped, active consent grant |
| **3 — Classification ceiling** | Any action on data whose level exceeds the deployment ceiling |
| **4 — Audit seal** | Any deletion or mutation of the provenance graph |
| **5 — Provenance (veto-as-default)** | Any irreversible+consequential action without a human checkpoint |

## Compliance

| Requirement | Aevum control |
|---|---|
| EU AI Act Article 12 (logging) | Episodic ledger: Ed25519+ML-DSA-65 dual-signed, SHA3-256-chained |
| GDPR Art. 6/9 (lawful basis) | Consent ledger: OR-Set grants, purpose-scoped, Cedar-enforced |
| GDPR Art. 17 (erasure) | Crypto-shredding: DEK destroyed on revoke, ciphertext unrecoverable |
| OWASP ASI01 (prompt injection) | Trifecta barrier: blocks untrusted-read + private-read + exfiltrate composition |
| OWASP ASI02 (data exfiltration) | Classification ceiling + trifecta Cedar policy |
| OWASP ASI04 (memory poisoning) | Sigchain: every entry chained, mutations detectable |
| NIST AI RMF MAP-1.6 | Structured audit pack exportable for any decision |

## Conformance

Aevum ships a machine-verifiable conformance suite:

```bash
pip install aevum-conformance
python -c "from aevum.conformance.suite import ConformanceSuite; \
    r = ConformanceSuite().run_all(); print(r.passed_count, '/', r.total_count)"
```

See [`docs/conformance_report.txt`](docs/conformance_report.txt) for the
reference run (9 invariants, generated from this codebase).

## Packages

| Package | Install | Purpose |
|---|---|---|
| `aevum-core` | `pip install aevum-core` | Kernel: five functions, sigchain, barriers, consent |
| `aevum-server` | `aevum-core[server]` | HTTP API wrapping all five functions |
| `aevum-store-oxigraph` | `aevum-core[oxigraph]` | Embedded RDF graph backend |
| `aevum-store-postgres` | `aevum-core[postgres]` | PostgreSQL graph + consent + ledger |
| `aevum-mcp` | `aevum-core[mcp]` | MCP tools for any MCP-compatible host |
| `aevum-cli` | `pip install aevum-cli` | `aevum server start`, `aevum store migrate` |
| `aevum-conformance` | `pip install aevum-conformance` | Machine-verifiable conformance suite |
| `aevum-agent` | `pip install aevum-agent` | A2A protocol integration |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

Security vulnerabilities: [GitHub Security Advisories](https://github.com/aevum-labs/aevum/security/advisories/new) (private disclosure).

## License

Code: Apache-2.0 · Specification: CC-BY-4.0 + OWFa 1.0.1
