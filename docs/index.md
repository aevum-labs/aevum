---
description: "Governed context kernel for AI agents: consent enforcement, tamper-evident Ed25519 sigchain, deterministic replay, and five absolute barriers."
---

# Aevum

**The governed context kernel for AI agents.**

AI agents that access sensitive data, take real-world actions, or make
decisions someone will need to explain later require more than a memory
layer. They need consent enforcement, a tamper-evident audit trail, and
human approval gates that cannot be bypassed.

Aevum provides all three — as a Python library you install and run
in your own infrastructure.

```bash
pip install aevum-core
```

---

## Is Aevum right for your project?

Answer these three questions:

**1. Does your agent take irreversible real-world actions?**
Sending emails, posting charges, modifying records, triggering deployments.

**2. Does your agent access data about more than one person or organisation?**
Multi-tenant SaaS, customer support, HR tools, healthcare platforms.

**3. Would you need to explain what your agent did?**
Regulatory audit, customer complaint, internal review, incident investigation.

If you answered yes to any of these, Aevum is worth evaluating.
Read the [full fit assessment](guides/fit-assessment.md) for a
detailed breakdown.

---

## What you get

| Capability | What it means |
|---|---|
| Consent enforcement | No data access without an active, scoped consent grant |
| Cryptographic audit trail | Every operation is Ed25519-signed and SHA3-256-chained |
| Deterministic replay | Reconstruct exactly what the agent knew at any past moment |
| Human review gates | Veto-as-default — silence past the deadline blocks the action |
| Five absolute barriers | Crisis, classification, consent, immutability, provenance — hardcoded |

---

## Where to go next

<div class="grid cards" markdown>

-   :material-rocket-launch: **New to Aevum?**

    Start with the quickstart — working code in under 10 minutes.

    [Quickstart →](getting-started/quickstart.md)

-   :material-help-circle: **Not sure if it fits?**

    Answer three questions and get an honest recommendation.

    [Fit Assessment →](guides/fit-assessment.md)

-   :material-domain: **Enterprise evaluation?**

    Security architecture, threat model, license analysis, and more.

    [Enterprise Package →](enterprise/overview.md)

-   :material-book-open: **Want to understand the design?**

    End-to-end data flow, the five functions, and the sigchain.

    [How It Works →](concepts/how-it-works.md)

</div>

---

## Open source

Apache-2.0 ·
[github.com/aevum-labs/aevum](https://github.com/aevum-labs/aevum)

Self-hosted — your data never leaves your infrastructure.
No vendor API. No telemetry. No SaaS dependency.
