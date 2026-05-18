---
description: "Aevum — the governed context kernel for AI agents.
Cryptographic audit trails, consent enforcement, and verifiable decision records."
---

# Aevum

**The Python library that makes your AI agent's memory accountable.**

Aevum is a Python library that gives AI agents a signed audit trail,
consent-checked data access, and verifiable decision records —
three problems that tend to surface together in production. The quickstart
gets you to working code in ten minutes.

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

</div>

## Install

```bash
pip install aevum-core
```

Apache-2.0. No telemetry. Runs fully offline.

Self-hosted — your data never leaves your infrastructure.
No vendor API. No licensing server. No SaaS dependency.

---

## See It in Action

Aevum governs its own development using its own governed functions.
The self-governance pipeline (`packages/aevum-maintainer`) demonstrates
what an Aevum-governed workflow looks like end-to-end.

**Self-governance pipeline status:**

| Phase | Deliverable | Status |
|---|---|---|
| 1 | Scaffold + compliance pack generator | Stub — scaffold and compliance pack done; OIDC ingest and Cedar policies not yet wired |
| 2 | MCP research interface (6 read-only tools) | Not implemented |
| 3 | Structured consent gate (HITL approval + dwell time) | Implemented — `POST /v1/consent/review` + `/approve` with sigchain recording |
| 4 | Replay endpoint + Rekor anchor + break-glass | Not implemented |
| 5 | Demo page (demo.aevum.build) | Not implemented |

Read how it works: [How Aevum Governs Itself](/learn/self-governance/)
