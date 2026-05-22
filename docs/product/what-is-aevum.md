# What is Aevum?

Aevum is a Python library that gives AI agents a signed audit trail,
consent-checked data access, and verifiable decision records — three
problems that tend to surface together in production. The quickstart
gets you to working code in ten minutes.

**Consent enforcement.** Data cannot be accessed without an active consent
grant that specifies exactly who can access it, for what purpose, and for
how long. Revoking consent takes effect at the next operation — no batch
job, no delay.

**A cryptographic audit trail.** Every operation produces a signed,
chained audit record. The record is tamper-evident: changing any past
entry breaks the cryptographic chain and is immediately detectable on
verification.

**Human approval gates.** Actions that require human sign-off cannot
proceed without a signed approval event in the audit trail. If no one
responds before the deadline, the action is blocked. Silence is a veto.

---

## What it is not

Aevum is not a memory framework. It does not replace Mem0, LangChain,
or LlamaIndex. It sits below those tools and makes whatever memory layer
you are using consent-gated and auditable.

Aevum is not a SaaS product. You install it in your own infrastructure.
Your data never leaves your environment.

Aevum is not an AI orchestration framework. It does not run agents or
manage workflows. It governs what happens when an agent accesses data.

Aevum does not make your application compliant with any regulation. It
provides technical controls — tamper-evident audit records, consent
documentation, and human-review gates — designed to support compliance
programs. Whether those controls satisfy a specific regulatory obligation
depends on your deployment, configuration, jurisdiction, and surrounding
controls. Aevum is not certified to any regulatory standard.

---

## Who it is for

Aevum is worth evaluating if one or more of these applies:

- Your agent accesses data about real people or organisations
- Your agent takes actions that are difficult to reverse
- Someone could later ask what your agent did and why
- You operate in a regulated industry (healthcare, finance, legal, HR)
- You have enterprise customers who ask about data governance

If none of those apply to your current project, Aevum is probably not
the right tool yet. See [Is It Right for You?](../index.md#who-it-is-for)
for a detailed assessment.

---

## How it works

Every operation passes through five unconditional barriers, requires an
active consent grant, and is recorded as a signed, chained audit event
before anything is written. The consent ledger tracks every grant and
revocation; the episodic ledger records every operation immutably.

Read [How It Works](../learn/architecture.md) for the complete
end-to-end data flow.

---

---

## v0.6.0 capabilities

**Zero-config developer mode.** Set `AEVUM_DEV=1` to get a fully working
Aevum engine with no consent configuration, no database, and no signer setup.
The quickstart is five minutes. The [Dev to Production checklist](../learn/dev-to-production.md)
shows what to replace before you deploy.

**Six adapters in CI.** Aevum ships production-ready governance adapters for:

| Adapter | Package extra | CI status |
|---|---|---|
| Anthropic Claude | `aevum-core[anthropic]` | ✓ Py 3.11–3.13 |
| LangChain | `aevum-core[langchain]` | ✓ Py 3.11–3.13 |
| LangGraph | `aevum-core[langgraph]` | ✓ Py 3.11–3.13 |
| OpenAI Agents | `aevum-core[openai-agents]` | ✓ Py 3.11–3.13 |
| CrewAI | `aevum-core[crewai]` | ✓ Py 3.11–3.13 |
| MCP | `aevum-core[mcp]` | ✓ 24 round-trip tests |

**AevumOTelBridge.** Routes sigchain events to any OTel backend as GenAI
spans. Privacy-preserving by default: only `audit_id` is emitted unless
content capture is explicitly opted in. Adds less than 0.5 ms p99 overhead.

**74/74 conformance.** The machine-verifiable conformance suite covers
74 invariants across sigchain format, dev mode contracts, OTel bridge
privacy defaults, and VaultTransitSigner key schemes. Run it against any
Aevum deployment:

```bash
pip install aevum-conformance
python -c "from aevum.conformance.suite import ConformanceSuite; \
    r = ConformanceSuite().run_all(); print(r.passed_count, '/', r.total_count)"
```

**Maintenance methodology.** The [Maintenance Playbook](../learn/playbook.md)
documents the four principles that govern how Aevum is developed: investigation
gate, inside-out ordering, known unknowns as first-class output, and mandatory
automation bias awareness at every consequential checkpoint.

---

## Get started

```bash
pip install aevum-core
export AEVUM_DEV=1  # zero-config developer mode
```

- [Quickstart](../getting-started/quickstart.md) — working code in five minutes
- [Dev to Production checklist](../learn/dev-to-production.md) — replace dev defaults before deploying
- [Installation](../learn/deployment.md) — all platforms including Docker
- [GitHub](https://github.com/aevum-labs/aevum) — Apache-2.0, source available
