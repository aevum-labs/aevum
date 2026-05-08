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
the right tool yet. See [Is It Right for You?](../guides/fit-assessment.md)
for a detailed assessment.

---

## How it works

Every piece of data that enters Aevum through `ingest` is:

1. Checked against five unconditional barriers (crisis, classification,
   consent, immutability, provenance)
2. Validated against an active consent grant
3. Written to the knowledge graph (`urn:aevum:knowledge`)
4. Recorded as a signed, chained audit event (`urn:aevum:provenance`)

Every `query` checks consent before returning any data.
Every `commit` appends to the immutable ledger.
Every `replay` retrieves and cryptographically verifies the signed record
of a past operation from the ledger. It does not re-execute agent
reasoning or reconstruct the full graph state at a past moment.

The five governed functions are: `ingest`, `query`, `review`,
`commit`, and `replay`.

Read [How It Works](../concepts/how-it-works.md) for the complete
end-to-end data flow.

---

## Get started

```bash
pip install aevum-core
```

- [Quickstart](../getting-started/quickstart.md) — working code in ten minutes
- [Installation](../getting-started/installation.md) — all platforms including Docker
- [GitHub](https://github.com/aevum-labs/aevum) — Apache-2.0, source available
