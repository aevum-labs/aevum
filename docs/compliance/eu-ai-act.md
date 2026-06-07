# EU AI Act

**Status:** Voluntary documentation (Recital 89)  
**Reference:** Regulation (EU) 2024/1689, in force 1 August 2024

---

## Aevum as a tool (Article 25(4) exemption)

Aevum is a third-party software tool and component. It is:

- **Not a GPAI model** — Aevum performs no inference, generation, or prediction. It is a
  context kernel that records, governs, and enables replay of AI decisions made by other
  systems.
- **Not a high-risk AI system** — Aevum does not make determinations that affect persons
  in the Annex III domains. It is infrastructure for AI systems.
- **Not a general-purpose AI model** — Aevum provides no AI capability. There are no
  model weights.

Under Article 25(4), providers of open-source tools and components that are not
themselves high-risk AI systems or GPAI models are exempt from the obligation to provide
written documentation to downstream high-risk AI system providers.

Recital 89 encourages providers of open-source AI components to voluntarily publish
technical documentation that assists downstream deployers in meeting their obligations.
This document is that voluntary documentation.

---

## Voluntary model card (Recital 89)

### Intended purpose

Aevum is a context kernel that sits between data sources and AI consumers. It provides:

- A governed ingestion membrane — all data enters through policy-evaluated `ingest()`
  calls
- An append-only episodic ledger — all decisions are cryptographically recorded
- Consent-checked graph traversal — no data access without an active consent grant
- Verifiable decision records — any past decision can be reconstructed with cryptographic proof

Aevum is intended to be operated by organizations deploying AI systems that process
personal data or make consequential decisions. It is not intended for end-user
deployment.

### Architecture

| Component | Role |
|---|---|
| Five public functions (ingest, query, review, commit, replay) | Stable, policy-evaluated API surface |
| Cedar policy engine | Attribute-based authorization; enforces unconditional barriers |
| Consent ledger (OR-Set CRDT) | Per-subject, per-purpose, time-bounded consent grants |
| Episodic ledger (sigchain) | Ed25519-signed, SHA3-256 Merkle-chained audit events |
| Unconditional barriers (5) | Non-configurable, non-overridable safety gates |

### Cryptographic primitives

| Primitive | Use |
|---|---|
| Ed25519 | Event signing (primary) |
| SHA3-256 | Merkle chain linking + payload hashing |
| ML-DSA 65 | Optional post-quantum dual-signing |
| RFC 3161 TSA | Optional trusted timestamping |
| AES-256-GCM | Per-subject DEK encryption in the consent ledger |

### Known limitations

- **Crisis detection (Barrier 1)** is keyword-based. The source code (`barriers.py`)
  states explicitly that it is not clinically validated, is not a medical device, and
  must not be the sole safety control for applications serving users in mental-health or
  crisis contexts. False negatives and false positives are possible.
- **Aevum does not evaluate AI model outputs.** Bias, fairness, accuracy, and robustness
  evaluation of AI models is outside Aevum's scope.
- **Aevum does not prevent non-compliant deployments.** It provides governance
  infrastructure, not compliance assurance. A deployer can configure weak policies or
  disable optional controls.
- **The NullPolicyEngine** (permissive fallback when no engine is configured) is suitable
  only for development and testing. Production deployments require a Cedar or OPA engine.

### Human oversight mechanisms

- The `review()` function halts a decision workflow pending human approval.
- Autonomy levels in `autonomy.cedar` (L1–L5) let operators require human approval for
  all consequential actions (L1) down to no restrictions (L5).
- All human decisions are recorded as sigchain entries, creating an auditable
  human-in-the-loop record.

---

## For adopters building high-risk AI systems (Annex III)

If you are building a high-risk AI system under Annex III, Aevum provides the following
toward your obligations under the AI Act.

### Article 12 — Logging requirements

Aevum's episodic ledger addresses the technical logging requirements of Article 12:

- **Automatic logging** of every governance decision — ingest, query, review, commit,
  replay — with timestamp, actor, event type, and payload hash.
- **Tamper-evident logging:** Ed25519 signatures and SHA3-256 Merkle chaining detect any
  modification to historical records.
- **Integrity verification:** `verify_chain()` provides a programmatic check that can be
  run at any time.
- **Decision reconstruction:** `replay()` reconstructs any past AI decision with its full
  context, satisfying the Article 12 requirement that logs enable post-hoc verification
  of the system's operation.

**Remaining deployer obligations:** Retain logs for the period required by applicable
sectoral law. Aevum does not enforce retention periods. You must also document the
logging design and make it available to notified bodies on request.

### Article 13 — Transparency and information provision

Aevum contributes to Article 13 requirements:

- The consent ledger provides an auditable record of what data was accessed, by whom,
  for what stated purpose, and under what authorization.
- The `authorization_ref` field of `ConsentGrant` can reference your legal basis for
  processing.
- The sigchain provides a verifiable record of operation that can be disclosed to
  affected persons on request.

**Remaining deployer obligations:** Article 13 requires instructions for use, capability
descriptions, and performance limitations for deployers and affected persons. Aevum does
not generate these for your system.

### Article 14 — Human oversight

Aevum's `review()` function and autonomy level configuration directly support Article 14.

**What Aevum provides:**

| Mechanism | Article 14 relevance |
|---|---|
| `review()` | Presents structured context to a human reviewer; halts execution until decision is recorded |
| Autonomy levels (L1–L5) | Operators require human approval for all consequential (L1), irreversible (L3), or no (L5) actions |
| Dwell time logging | Time between `review()` and human decision is recorded in the sigchain |
| Blast radius disclosure | Review contexts include provenance, enabling the reviewer to assess data scope and action impact |

**What "meaningful oversight" requires beyond Aevum:**

Article 14(4) requires that human overseers have the competence, authority, and tools to
understand the AI system's capabilities and limitations. Aevum provides the audit record
and the review gate. Deployers must ensure that:

- Human reviewers are trained on the specific AI system being overseen.
- Reviewers have sufficient time for substantive review — not rubber-stamp approval flows.
- Reviewers have authority to halt or override the AI system.
- The context presented by `review()` is meaningful to the reviewer's domain expertise.

---

## References

- Regulation (EU) 2024/1689 — EU AI Act
- Article 25(4): Third-party tools and components exemption
- Recital 89: Voluntary documentation for open-source components
- Article 12: Logging requirements for high-risk AI systems
- Article 13: Transparency and information provision
- Article 14: Human oversight
- Annex III: High-risk AI system use cases
- `packages/aevum-core/src/aevum/core/barriers.py` — Unconditional barriers
- `packages/aevum-core/src/aevum/core/consent/models.py` — ConsentGrant
- `packages/aevum-core/src/aevum/core/policies/autonomy.cedar` — L1–L5 autonomy levels
