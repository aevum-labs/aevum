# Aevum

**The independent black box for AI agents.** Tamper-evident, independently
verifiable records of what your agents did — so when an auditor, regulator, or
court asks you to prove it, you can.

Aevum records every agent action into a cryptographically signed, hash-chained
ledger (a *sigchain*) and wraps each entry in a portable signed receipt
(COSE_Sign1 + RFC 3161 trusted timestamp) that anyone can verify — without
trusting Aevum, your model provider, or your cloud. It is the flight recorder,
not the autopilot: a neutral evidence layer alongside whatever agent stack you
already run.

[![CI](https://github.com/aevum-labs/aevum/actions/workflows/ci.yml/badge.svg)](https://github.com/aevum-labs/aevum/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/aevum-core)](https://pypi.org/project/aevum-core/)
[![Python](https://img.shields.io/pypi/pyversions/aevum-core)](https://pypi.org/project/aevum-core/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

## Why a black box, and why *independent*

A flight recorder matters not because the airline keeps logs — it matters
because the recorder is **independent, tamper-evident, and admissible**: an
outside investigator reads it, and it holds up under challenge. Most AI logging
today is the opposite. Observability tools (OpenTelemetry, Langfuse, Datadog)
and cloud-native agent logs (Bedrock, Foundry, Vertex) are **mutable,
self-attested, and operator-controlled** — excellent for debugging, weak as
evidence. The operator is logging its own behavior, and nothing stops the record
from being changed after the fact.

Aevum produces records that are:

- **Tamper-evident** — every entry is Ed25519-signed and SHA3-256 hash-chained;
  altering any past entry breaks the chain and fails verification.
- **Independently verifiable** — a third party verifies a receipt with the
  public key alone (`aevum verify`). No access to your systems required.
- **Portable and timestamped** — each entry is wrapped in a COSE_Sign1 receipt
  with an RFC 3161 trusted timestamp, and can be anchored to a public
  transparency log (Rekor v2).
- **Built for the record-keeping rules you already face** — designed to be
  auditor- and court-defensible (an FRE 902(13) self-authentication
  certification template is included in `docs/legal/`).

## The problem it solves

When an autonomous agent does something consequential — moves money, touches
PII, takes an irreversible action — three questions follow, and the standard
stack cannot answer them with evidence that survives a challenge:

1. **What did the agent actually do, and in what order?** Mutable logs can be
   edited; you cannot prove they were not.
2. **Can you prove it to someone who does not trust you?** Self-attested logs
   are worth little to a regulator or an opposing party.
3. **Will it still hold up months from now?** Records must be retained and
   remain verifiable long after the event (EU AI Act Art. 12 ≥6-month retention;
   SEC 17a-4; FDA 21 CFR Part 11.10(e); HIPAA §164.312(b)).

Aevum makes the record **structural rather than procedural**: the evidence is
produced as a byproduct of the agent running, not bolted on after an incident.

## Quick start (zero config)

```bash
pip install aevum-core
export AEVUM_DEV=1
```

```python
from aevum.core import Engine

engine = Engine()  # AEVUM_DEV=1 grants consent automatically
result = engine.ingest(
    data={"message": "User asked about billing"},
    provenance={"source_id": "support-chat", "chain_of_custody": ["support-chat"],
                "classification": 0},
    purpose="customer-support", subject_id="user-42", actor="my-agent",
)
print(result.audit_id)   # urn:aevum:audit:<uuid7>  — signed, chained, replayable
print(result.status)     # ok
```

`AEVUM_DEV=1` is for local development only — see the
[Dev to Production checklist](https://github.com/aevum-labs/aevum/blob/main/docs/learn/dev-to-production.md)
before deploying. For explicit consent grants, see the
[Pure Python guide](https://github.com/aevum-labs/aevum/blob/main/docs/learn/guides/pure-python.md).

> **For coding agents:** [`llms.txt`](https://aevum.build/llms.txt) and
> [`llms-full.txt`](https://aevum.build/llms-full.txt) provide machine-readable
> API summaries for use with Claude, Copilot, and similar tools.

## Record from the framework you already use

Aevum attaches to your existing stack as a recorder. Eight adapters ship with CI
coverage across Python 3.11–3.13:

| Adapter | Install | Import path |
|---|---|---|
| LangGraph checkpointer | `aevum-core[langgraph]` | `aevum.core.adapters.langgraph.AevumCheckpointer` |
| Anthropic SDK | `aevum-core[anthropic]` | `aevum.core.adapters.anthropic_adapter.AevumAnthropicAdapter` |
| LangChain | `aevum-core[langchain]` | `aevum.core.adapters.langchain_callback.AevumLangChainCallback` |
| OpenAI Agents | `aevum-core[openai-agents]` | `aevum.core.adapters.openai_agents.AevumAgentHooks` |
| CrewAI | `aevum-core[crewai]` | `aevum.core.adapters.crewai.AevumCrewHooks` |
| MCP | `aevum-core[mcp]` | `aevum.mcp.traceparent` |
| Google ADK | `aevum-core[adk]` | `aevum.core.adapters.adk.AevumADKCallback` |
| Microsoft Agent Framework | `aevum-core[maf]` | `aevum.core.adapters.maf.AevumMAFMiddleware` |

```python
# LangGraph drop-in — every superstep signed and hash-chained
from aevum.core.adapters.langgraph import AevumCheckpointer
checkpointer = AevumCheckpointer.local()
graph = builder.compile(checkpointer=checkpointer)
# delete_thread(thread_id) → GDPR Art. 17 crypto-erasure
```

> Adapters **record** agent activity into the sigchain and apply policy checks.
> The five unconditional barriers (below) run in Aevum's own **kernel** path —
> route enforcement-critical actions through the kernel when you need them
> enforced, not just recorded.

## Install

```bash
pip install aevum-core                     # kernel only
pip install "aevum-core[server]"           # + HTTP API
pip install "aevum-core[langgraph]"        # + LangGraph checkpointer
pip install "aevum-core[anthropic]"        # + Anthropic SDK adapter
pip install "aevum-core[langchain]"        # + LangChain callback
pip install "aevum-core[openai-agents]"    # + OpenAI Agents SDK
pip install "aevum-core[crewai]"           # + CrewAI hooks
pip install "aevum-core[oxigraph]"         # + embedded RDF graph
pip install "aevum-core[postgres]"         # + PostgreSQL backend
pip install "aevum-core[mcp]"              # + MCP integration
pip install "aevum-core[all]"              # everything
```

> **Note:** The bare name `aevum` on PyPI is an unrelated project.
> Always use `aevum-core` (or another `aevum-*` package).

## Supporting layer: the governed kernel

Beyond recording, Aevum includes an optional governed execution path — five
functions and five hardcoded safety barriers — for teams that want enforcement,
not just evidence.

### The five functions (CRE protocol)

| Function | Protocol verb | What it does |
|---|---|---|
| `ingest` | RELATE | Write data through the governed membrane |
| `query` | NAVIGATE | Traverse the graph for a declared purpose |
| `review` | GOVERN | Present context for human decision |
| `commit` | REMEMBER | Append event to the episodic ledger |
| `replay` | (no verb) | Reconstruct any past decision faithfully |

In the kernel path, all five are consent-checked, barrier-enforced, and
ledger-recorded.

### The five unconditional barriers

The five barriers are enforced as **hardcoded checks in `barriers.py` that run first, on every operation, before the policy engine** — independent of any operator setting, environment variable, or runtime argument, and not bypassed even by dev mode (`AEVUM_DEV=1`). If a barrier fires, the operation halts. The same five are **also expressed as Cedar `forbid` policies (`barriers.cedar`)**, enforced by the policy engine when the `[cedar]` extra is installed — defense-in-depth: the hardcoded layer is the unconditional guarantee (it fires even without Cedar); the Cedar layer is a redundant expression.

| Barrier | What it blocks |
|---|---|
| **1 — Crisis** | Any graph write when crisis-signal keywords are detected |
| **2 — Classification Ceiling** | Any action on data whose level exceeds the deployment ceiling |
| **3 — Consent** | Any context traversal without a scoped, active consent grant |
| **4 — Audit Immutability** | Any deletion or mutation of the provenance graph |
| **5 — Provenance** | Any irreversible+consequential action without a human checkpoint |

## Compliance

| Requirement | Aevum control |
|---|---|
| EU AI Act Article 12 (logging) | Episodic ledger: Ed25519-signed, SHA3-256-chained, ≥6-month retention; optional ML-DSA-65 post-quantum signing |
| SEC 17a-4 / FINRA 4511 (broker-dealer records) | Audit-trail alternative: records reconstructable after modification, with verified authenticity |
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
reference run. The v0.7.4 suite covers 74 invariants across sigchain format,
dev mode contracts, OTel bridge privacy defaults, and VaultTransitSigner key
schemes.

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

## Self-governance pipeline

Aevum governs its own maintenance workflow using its own governed functions — a
working dogfood of the library. Implementation in `packages/aevum-maintainer`:

| Phase | Deliverable | Status |
|---|---|---|
| 1 | Scaffold + compliance pack generator | Implemented — OIDC ingest, Cedar policies, compliance pack generation |
| 2 | MCP research interface (6 read-only tools) | Implemented — `GET /v1/mcp/{tool_name}` (sigchain, reviews, test count, backlog, integrity) |
| 3 | Structured consent gate (HITL approval + dwell time) | Implemented — `POST /v1/consent/review` + `/approve` with sigchain recording |
| 4 | Replay endpoint + Rekor anchor + break-glass | Implemented — `GET /v1/replay/{audit_id}`, Rekor v2 anchoring, `POST /v1/break-glass` |
| 5 | Demo page (demo.aevum.build) | Implemented — served at `GET /` |

## Maintainer

Aevum is actively maintained by
[@bnyhil](https://github.com/bnyhil) under the
[aevum-labs](https://github.com/aevum-labs) GitHub
organization. This is a solo open-source research project
— not a commercial product or formal legal entity.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

Security vulnerabilities: [GitHub Security Advisories](https://github.com/aevum-labs/aevum/security/advisories/new) (private disclosure).

## License

Code: Apache-2.0 · Specification: CC-BY-4.0 + OWFa 1.0.1
