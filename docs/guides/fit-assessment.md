---
description: "Four questions to determine if Aevum fits your project: agent-over-people data, regulatory obligations, deployment model, and engineering capacity."
---

# Is Aevum Right for You?

Answer these questions honestly. They take 5 minutes and give you a clear answer.

## Question 1: Do you have an AI agent making decisions about people?

If yes, Aevum is relevant.

If no (your AI generates content, summarizes documents, or assists with tasks
that don't involve personal data), Aevum adds governance overhead without
a corresponding benefit. Stop here.

---

## Question 2: Do any of these apply to your situation?

- You operate in a regulated industry (healthcare, finance, legal, insurance, HR)
- You have GDPR, HIPAA, SOX, or CCPA obligations
- Your AI agent makes decisions that affect individuals (credit, hiring, medical, benefits)
- You need to prove to auditors what your AI saw at the time it made a decision
- You need a human-in-the-loop before your AI takes irreversible actions

If **one or more** apply: Aevum is a strong fit.

If **none** apply: Aevum may still be useful for auditability, but the
governance machinery is significant. Consider whether simpler logging
would meet your needs.

---

## Question 3: What is your deployment model?

| You want | Aevum fit |
|---|---|
| A Python library you control entirely | Excellent |
| An on-premise or private cloud deployment | Excellent |
| A managed SaaS where you don't control the infrastructure | Not applicable (Aevum is self-hosted only) |
| A serverless/stateless architecture | Possible, but requires external storage backend |

---

## Question 4: What is your team size and engineering capacity?

Aevum requires:
- Python 3.11+
- Engineering time to write your integration layer (the code that calls Aevum)
- Database infrastructure (if you want persistence — Oxigraph or PostgreSQL)
- Optional: OPA sidecar for infrastructure policy

**Minimum viable setup:** 1 engineer, 1 afternoon, no database.
**Production setup:** 1-2 engineers, 1-2 weeks, PostgreSQL.

---

## When Aevum is a strong fit

✓ You have AI agents making decisions about people  
✓ You have regulatory obligations or audit requirements  
✓ You need deterministic replay of past decisions  
✓ You need consent-gated data access  
✓ You want human review gates before irreversible actions  
✓ You want tamper-evident audit trails without building them yourself  

---

## When Aevum is not the right tool

✗ Your AI agent generates content, not decisions about people  
✗ You need a real-time streaming pipeline (use Kafka, Pulsar, or NATS)  
✗ You need an AI orchestration framework (use LangChain, LlamaIndex, etc.)  
✗ You need a managed compliance reporting SaaS  
✗ You need a general-purpose graph database  

---

## Common mismatches

**"We just need audit logging."**

If you only need to log what your AI did, a structured logging library
(structlog, OpenTelemetry) with a centralized log store is simpler.
Aevum adds: consent enforcement, classification ceilings, human review gates,
and replay. If you don't need those, you don't need Aevum.

**"We have a no-code AI platform."**

Aevum is a Python library. If you can't write Python that calls the kernel,
you can use `aevum-mcp` from an MCP-compatible host (Claude Desktop, Cursor,
etc.), but the integration layer still needs to be built.

**"We need Aevum to move data between systems."**

Aevum is not a data integration platform. It governs access; your integration
layer moves data. See [Building an Integration Layer](integration-layer.md).

---

## Still not sure?

Open a [GitHub Discussion](https://github.com/aevum-labs/aevum/discussions)
and describe your use case. The community can help you decide.
