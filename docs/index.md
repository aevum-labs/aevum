---
description: "Aevum — the independent black box for AI agents.
Tamper-evident, independently verifiable records of agent actions for audit, compliance, and forensics."
---

# Aevum

**The independent black box for AI agents.**

Aevum records what your AI agents do into a tamper-evident, independently
verifiable ledger — signed, hash-chained, and timestamped — so you can prove
what happened to an auditor, regulator, or court without asking them to trust
you. It attaches to your existing agent stack as a recorder; an optional
governed kernel adds consent enforcement and hardcoded safety barriers.
The quickstart gets you to working code in ten minutes.

!!! tip "Developer"
    New here? Start with `AEVUM_DEV=1` — [Quickstart →](/getting-started/quickstart/)

!!! note "Compliance"
    Evaluating for EU AI Act Article 12? — [Article 12 guide →](/compliance/article12/)

!!! abstract "Security"
    Reviewing the threat model? — [THREAT_MODEL.md →](https://github.com/aevum-labs/aevum/blob/main/THREAT_MODEL.md)

!!! success "Skeptical?"
    Don't take our word for it — [verify a chain yourself →](/verify/)

## Where to start

<div class="grid cards" markdown>

-   :material-book-open-variant:{ .lg } **Understand it first**

    How Aevum works: the governed membrane, the sigchain, the five
    barriers, and the consent model — in one page.

    [:octicons-arrow-right-24: Architecture](/learn/architecture/)

-   :material-rocket-launch-outline:{ .lg } **Build with it**

    First governed session in under 10 minutes.
    Works on Linux, macOS, and Windows.

    [:octicons-arrow-right-24: Quickstart](/getting-started/quickstart/)

-   :material-shield-search:{ .lg } **Evaluate it**

    Threat model, security architecture, and common security questions
    for engineers evaluating production deployment.

    [:octicons-arrow-right-24: Security](/learn/security/)

-   :material-check-decagram-outline:{ .lg } **Prove it**

    Verify a signed chain or auditor evidence pack yourself, with the
    standalone `aevum-verify` tool — copy-paste, no Aevum install required.

    [:octicons-arrow-right-24: Verify](/verify/)

</div>

## Install

```bash
pip install aevum-core
```

Apache-2.0. No telemetry. Runs fully offline.

Self-hosted — your data never leaves your infrastructure.
No vendor API. No licensing server. No SaaS dependency.

## Who It Is For {#who-it-is-for}

Aevum is useful when your AI agent needs to answer any of these questions:

- *"What did the agent know when it made this decision?"* — `replay()`
- *"Did the agent have permission to access this data?"* — consent ledger
- *"Has this audit trail been tampered with?"* — `verify_sigchain()`
- *"Was a human in the loop for this action?"* — `review()`

**Good fit:** Regulated industries (healthcare, finance, legal), agentic
workflows that touch PII or sensitive data, compliance-driven environments
(EU AI Act, HIPAA, SOC 2), and teams that need to demonstrate audit
accountability to customers or regulators.

**Not a fit yet:** If you need a streaming data platform, an AI orchestration
framework, a database, or an agent execution runtime — Aevum is not those
things. See [What Aevum Is Not](/product/what-is-aevum/) for the normative list.

---

## See It in Action

Aevum governs its own development using its own governed functions.
The self-governance pipeline ([aevum-labs/aevum-maintainer](https://github.com/aevum-labs/aevum-maintainer)) demonstrates
what an Aevum-governed workflow looks like end-to-end.

**Self-governance pipeline status:**

| Phase | Deliverable | Status |
|---|---|---|
| 1 | Scaffold + OIDC ingest + Cedar policies | ✅ Complete |
| 2 | MCP research interface (6 read-only tools) | ✅ Complete |
| 3 | Structured consent gate (HITL approval + dwell time) | ✅ Complete |
| 4 | Replay endpoint + Rekor anchor + break-glass | ✅ Complete |
| 5 | Demo page | ✅ Complete — [demo.aevum.build](https://demo.aevum.build) |

Read how it works: [How Aevum Governs Itself](/learn/self-governance/)
