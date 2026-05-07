---
description: "How Aevum aligns with OpenTelemetry GenAI conventions, the IETF
Agent Audit Trail draft, EU AI Act Article 12, NIST AI RMF, and the OWASP
Top 10 for Agentic Applications."
---

# Standards and Regulatory Alignment

Aevum does not invent its own audit record format. The sigchain, the
pre-call envelope, and the consent model are designed to implement
emerging standards rather than compete with them. This page maps
Aevum's primitives to the relevant standards.

---

## OpenTelemetry GenAI semantic conventions

Aevum's `aevum-llm` package maps `AuditEvent` fields to the
[OTel GenAI semantic conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/)
via `to_otel_attributes()`.

```python
from aevum.llm.otel import to_otel_attributes

attrs = to_otel_attributes(audit_event)
# attrs["gen_ai.request.model"]    → model requested
# attrs["gen_ai.response.model"]   → model that responded
# attrs["gen_ai.system"]           → provider ("openai", "anthropic", …)
# attrs["gen_ai.operation.name"]   → operation type ("chat", …)
# attrs["gen_ai.content.reference"]→ audit_id (external storage reference)
# attrs["aevum.gen_ai.prompt_hash"]→ SHA3-256 of prompt (not the prompt)
# attrs["aevum.gen_ai.response_hash"]→ SHA3-256 of response (not the response)
```

**Privacy posture:** Aevum uses OTel's "external storage" mode. Raw prompts
and responses are never emitted. The `audit_id` is the reference — it
points to the tamper-evident, signed record in the episodic ledger.
The consumer retrieves content via `engine.replay(audit_id=...)` with
a valid consent grant.

**OTel fields captured automatically by `LlmComplication`:**

| OTel GenAI key | Aevum source |
|---|---|
| `gen_ai.request.model` | LiteLLM model string |
| `gen_ai.response.model` | LiteLLM response object |
| `gen_ai.system` | Provider prefix from model string |
| `gen_ai.operation.name` | Always `"chat"` for completions |
| `gen_ai.conversation.id` | Caller-supplied `model_context` |

---

## IETF Agent Audit Trail

The [IETF Agent Audit Trail draft](https://datatracker.ietf.org/doc/draft-sharif-agent-audit-trail/)
(`draft-sharif-agent-audit-trail-00`) specifies an audit record format using
SHA-256 per RFC 8785 JCS canonicalization with optional ECDSA signatures.
It explicitly cites EU AI Act Article 12 as motivation.

Aevum's `aevum-sdk` exports a parallel IETF-format chain:

```python
from aevum.sdk.export.ietf_aat import export_sigchain

events = engine.get_ledger_events()  # or equivalent
records = export_sigchain(events)
# records[0]["agent_id"]      → actor
# records[0]["action_type"]   → event_type
# records[0]["outcome"]       → "success" | "failure" | "pending"
# records[0]["timestamp"]     → valid_from (ISO 8601)
# records[0]["prior_hash"]    → SHA-256 JCS of previous record
# records[0]["chain_hash"]    → SHA-256 JCS of this record
# records[0]["aevum:audit_id"]→ internal audit_id (cross-reference)
```

**Two chains coexist:** Aevum's internal sigchain uses SHA3-256 for
tamper detection (`engine.verify_sigchain()`). The IETF export produces
a parallel SHA-256 JCS chain for external interoperability. Both are
derived from the same AuditEvent data.

!!! warning "Draft status"
    `draft-sharif-agent-audit-trail-00` expires September 2026 and has not
    been adopted as an IETF standard. Aevum implements against the draft
    format for forward compatibility. Field names may change before
    standardization.

---

## EU AI Act Article 12

Article 12 of Regulation (EU) 2024/1689 requires high-risk AI systems to
"technically allow for the automatic recording of events (logs) over the
lifetime of the system."

**What Aevum provides:**

| Art. 12 requirement | Aevum implementation |
|---|---|
| Automatic recording | Every engine call appends to the episodic ledger unconditionally (Barrier 4) |
| Tamper-evident | Ed25519 + SHA3-256 hash chain; `verify_sigchain()` detects any modification |
| Traceable to inputs | Pre-call context stored in `AuditEvent.payload` with `payload_hash` |
| Actor identity | `actor` field required, non-empty (enforced by `AuditEvent.__post_init__`) |
| Purpose declaration | `purpose` field required on all data operations |

**Retention:** Art. 26(6) requires a minimum six months (183 days).
Aevum records are append-only by design (Barrier 4) — deletion requires
external database action outside the kernel.

**Reference policy bundle:** See
`packages/aevum-core/policies/opa/eu-ai-act-art12.rego` for an OPA
policy that gates operations on Art. 12 session requirements.
[Reference example only — consult legal counsel before production use.]

**Deployment note:** Art. 12 requires that the recording happens
automatically and cannot be disabled. Pattern 2 or Pattern 3 from
[Deployment Patterns](/learn/deployment-patterns/) provides the
infrastructure-level guarantee that the recording path is always traversed.

---

## NIST AI RMF

NIST AI RMF 1.0 (January 2023) and the Generative AI Profile (AI 600-1,
July 2024) organize AI risk management across four functions: GOVERN,
MAP, MEASURE, MANAGE.

| RMF function | Aevum primitive |
|---|---|
| GOVERN — policies and accountability | Cedar / OPA policy bundles; five barriers as unconditional governance layer |
| MAP — risk identification | `review` function (GOVERN verb) with L1–L5 autonomy levels |
| MEASURE — risk measurement | Episodic ledger provides the evidence base; `replay` enables incident reconstruction |
| MANAGE — risk mitigation | Consent enforcement (Barrier 3); classification ceiling (Barrier 2); crisis detection (Barrier 1) |

The NIST RMF Agentic Profile (CSA Lab Space, 2025) extends RMF 1.0 to
tool-using agents. Aevum's consent model maps to its "minimal permission"
and "human-in-the-loop" controls.

---

## OWASP Top 10 for Agentic Applications

[OWASP Top 10 for Agentic Applications 2025](https://owasp.org/www-project-top-10-for-agentic-ai-applications/)

| Risk | Aevum coverage | Notes |
|---|---|---|
| **Goal / task hijacking** (prompt injection) | Partial — records context, does not filter | Use Lakera Guard or NeMo Guardrails for content filtering |
| **Tool misuse** (unauthorized tool calls) | Addresses — consent required per operation; denials logged | Combine with MCP gateway for mandatory enforcement |
| **Identity / permission abuse** | Addresses — `actor` required; consent scoped by `grantee_id` and `purpose` | **OWASP ASI03:** With `aevum-spiffe` (requires SPIFFE/SPIRE deployment), agent identity is cryptographically attested via JWT-SVID, recorded in `spiffe.attested` events. Coverage improves to 🔧 REQUIRES CONFIG. |
| **Memory / knowledge poisoning** | Addresses — Barrier 3 blocks writes without consent; classification ceiling limits read access | |
| **Code / plugin execution** | Out of scope | Use gVisor, Firecracker, NVIDIA OpenShell |
| **Insecure agent communications** | Out of scope | Use TLS/mTLS on the transport layer |
| **Data exfiltration** | Partial — classification ceiling (Barrier 2) restricts data access | Does not redact at the model boundary |
| **Insufficient human oversight** | Addresses — `review` function (GOVERN verb) with configurable autonomy levels L1–L5 | |
| **Supply chain compromise** | Out of scope | Use SBOM / SLSA / Sigstore on releases |
| **Rogue / shadow agents** | Partial — consent required for all kernel operations; sigchain creates accountability trail | Does not prevent agents from bypassing the kernel |

---

## External chain verification

**Sigstore Rekor v2 / Transparency logs:** With `aevum-publish`,
chain checkpoints are submitted to an external Signed Tree Head log,
enabling adversarial-resistant verification. Without this, tamper-detection
requires the verifier to trust the operator. With this, tampering is
detectable by any party with access to the Rekor log.

---

## What Aevum does not cover

Regulatory scope is as important as coverage:

**Aevum produces evidence — it does not interpret it.** The episodic ledger
is the technical artifact. A compliance program, legal team, or
compliance-reporting tool interprets whether that artifact satisfies
a specific regulatory obligation.

**Aevum does not generate compliance reports.** It provides the signed,
tamper-evident records that feed a compliance report.

**Sector-specific overlays are not built in.** HIPAA minimum-necessary,
FDA SaMD logging requirements, FINRA trade-surveillance requirements,
and NIS2 incident-reporting timelines all layer on top of the general
AI-governance requirements covered here. Reference policy bundles for
HIPAA are in `packages/aevum-core/policies/opa/`.

## See also

- [Architecture](/learn/architecture/) — the five barriers and sigchain
- [Deployment Patterns](/learn/deployment-patterns/) — enforcement architecture
- [Audit Trails and Article 12](/concepts/audit-trails/) — detailed Art. 12 guide
- [Memory Poisoning Defense](/concepts/memory-poisoning/) — OWASP risk detail
