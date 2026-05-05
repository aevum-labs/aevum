---
description: "Aevum — the governed context kernel for AI agents.
Cryptographic audit trails, consent enforcement, and deterministic replay."
---

# Aevum

**The governed context kernel for AI agents.**

Aevum is an open-source Python library that sits between your AI agents and
the data they reason over. Where observability tools log what happened after
the fact, Aevum enforces governance before the agent acts — and records a
cryptographically signed, hash-chained audit trail that makes every past
decision deterministically replayable.

## Enforcement before the agent acts

Three properties that AI agents do not have by default:

1. **Consent enforced at the kernel level** — data cannot be accessed without
   an active consent grant that specifies exactly who can access it, for what
   purpose, and for how long. Revoking consent takes effect at the next operation.
   No batch job, no delay. This fires before any policy evaluation, even without
   Cedar installed.

2. **Replay from an immutable sigchain** — every operation is signed with Ed25519
   and hash-chained with SHA3-256. `engine.replay(audit_id=...)` reconstructs
   any past decision exactly as it occurred — same payload, same metadata — not
   a re-execution against a new model. Any modification to the ledger is
   immediately detectable.

3. **Five absolute barriers** — crisis detection, classification ceiling, consent
   enforcement, audit immutability, and provenance checks are hardcoded in
   `barriers.py`. They are not configurable. They cannot be bypassed by
   configuration, policy, or administrator override.

## Who it is for

**Individual developers and startups** building agents that access data about
real people — healthcare, finance, legal, HR, customer support. Aevum gives
you consent enforcement and a tamper-evident audit trail without building
custom infrastructure. Minimum viable setup: one afternoon, no database.

**Enterprise teams with compliance requirements** — HIPAA, GDPR Article 7,
SOX, FCRA. The episodic ledger produces the evidence an auditor needs: every
data access, every consent grant, every human approval, replayable on demand.
Runs fully self-hosted — your data never leaves your infrastructure.

**Anyone who needs to answer "what did the agent do, and why?"** — incident
investigation, customer complaints, regulatory audit, internal review.

Aevum is not for you if your agent generates content without accessing personal
data, or if you need a streaming pipeline, an orchestration framework, or a
managed SaaS. See [fit assessment details in the Architecture page](/learn/architecture/).

## Where to start

**Understand it first**

→ [Architecture](/learn/architecture/) — how Aevum works: the governed
membrane, the sigchain, the five barriers, and the consent model — one page.

**Build with it**

→ [Quickstart](/getting-started/quickstart/) — first governed session in
under 10 minutes. Works on Linux, macOS, and Windows.

**Evaluate it**

→ [Security](/learn/security/) — threat model, security architecture, and
common security questions for engineers evaluating production deployment.

## Install

```bash
pip install aevum-core
```

Apache-2.0. No telemetry. Runs fully offline.

Self-hosted — your data never leaves your infrastructure.
No vendor API. No licensing server. No SaaS dependency.
