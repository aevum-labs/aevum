# ADR-008: Multi-agent episode correlation

Date: 2026-05-06
Status: Accepted
Deciders: Aevum Labs
Confidence: Medium

## Context and Problem Statement

AI systems increasingly involve multiple cooperating agents: an orchestrator calls a
specialist, which calls a tool, which calls a sub-agent. Each agent runs its own
Aevum Engine with its own sigchain. When an auditor investigates an incident, they
need to reconstruct the full causal chain across agents — not just within one
agent's chain.

Current state: `episode_id` groups events within one chain. `causation_id`
references events within the same chain. Neither mechanism supports cross-chain
causal linking.

`AuditEvent` already carries `trace_id: str | None` and `span_id: str | None` as
first-class fields (alongside `episode_id` and `causation_id`). These fields were
included in the schema for exactly this purpose but the propagation convention has
not been specified.

Open questions:
1. How should `episode_id` and `trace_id` propagate across agent boundaries?
2. How should cross-chain causal references be represented?
3. Can the approach be validated against an existing multi-agent protocol?

## Decision Drivers

- NIST AI RMF GOVERN 4.3: accountability documentation across the AI system
- EU AI Act Art. 12(2)(b): identify persons responsible — in multi-agent systems
  this requires knowing which agent caused which action
- A2A protocol compatibility: A2A (Agent-to-Agent, v1.0.0-rc) uses OTLP spans
  with `traceparent`; Aevum must not conflict with it
- Backward compatibility: single-agent deployments must not be affected
- Forensic completeness: a verifier must be able to follow the causal chain across
  agents given access to all chains

## Considered Options

1. **W3C Trace Context for propagation + `cross_chain_ref` payload field (this decision)**
2. Shared sigchain across agents
3. `episode_id` matching only (no cross-chain causal references)
4. Delegate to A2A task-level audit (external to Aevum)

**Option 1** — Use W3C Trace Context (`traceparent` header, W3C TR 2021) to
propagate distributed trace identity across agent boundaries. The calling agent's
`traceparent` trace-id populates `AuditEvent.trace_id` (already a first-class
field); `episode_id` within each agent's chain is mapped to the trace-id so that
all events in a distributed episode share a common `trace_id`. A new optional
payload field `cross_chain_ref` enables explicit causal linking: an event caused
by an event in another agent's chain carries a `cross_chain_ref` dict in its
payload containing enough information to locate and verify the referenced event.

**Option 2** — All agents write to the same sigchain. Eliminates the cross-chain
problem, but requires a shared ledger and a single signing key — destroying agent
autonomy and creating a single point of failure. Not viable for distributed
deployments.

**Option 3** — Correlate by matching `episode_id` across multiple chains only.
Sufficient for grouping but does not establish causal order or validate that the
cross-agent link is authentic. An adversary could forge an `episode_id` match
without leaving cryptographic evidence.

**Option 4** — Rely on the A2A protocol's own task management and audit mechanisms.
Valid if A2A provides sufficient audit coverage — but A2A explicitly delegates
audit-record format to the application layer, which is exactly what Aevum provides.

## Decision Outcome

Option 1. W3C Trace Context for distributed trace propagation using the existing
`trace_id` and `span_id` fields; `cross_chain_ref` as an optional payload field
for explicit causal linking.

**Propagation convention:** The calling agent injects a `traceparent` header into
the A2A call. The called agent extracts the trace-id from `traceparent` and records
it in every `AuditEvent.trace_id` for the duration of that episode. Both agents'
events share the same `trace_id`. The `episode_id` within each agent's own chain
remains locally generated (UUID v7) and is not overwritten — `trace_id` is the
cross-chain correlation key.

**Cross-chain causal reference:** A new optional payload field `cross_chain_ref`
on any AuditEvent caused by an event in another agent's chain:

```json
{
  "cross_chain_ref": {
    "trust_domain": "spiffe://billing.example.org",
    "agent_id": "billing-agent-3f7a",
    "episode_id": "01961234-5678-7abc-def0-123456789012",
    "system_time": 1746000000000000000,
    "event_hash": "<64-hex-SHA3-256>"
  }
}
```

`event_hash` is `AuditEvent.hash_event_for_chain(referenced_event)` — the same
SHA3-256 function already used for sigchain construction. This allows a verifier to
confirm the referenced event exists in the referenced chain without trusting the
reference itself.

`causation_id` retains its existing semantics: within-chain only. It is not used
for cross-chain references. `cross_chain_ref` in the payload is the cross-chain
mechanism.

### Authorised Part 2 code scope

No new package is required. The implementation is:

1. **SDK helper (aevum-sdk):** `aevum.sdk.correlation` module providing:
   - `extract_trace_id_from_traceparent(header: str) -> str | None`
   - `inject_traceparent(trace_id: str, span_id: str) -> str`
   - `build_cross_chain_ref(event: AuditEvent) -> dict`

2. **Documentation:** update the episode_id and trace_id documentation to specify
   the W3C Trace Context mapping and the `cross_chain_ref` payload convention.

3. **No aevum-core changes:** `trace_id` and `span_id` are already first-class
   `AuditEvent` fields; `cross_chain_ref` goes in `AuditEvent.payload` (open
   `dict`); the SDK helper populates it before the caller passes the payload to
   the kernel.

### Verification procedure for cross-chain links

An auditor with access to multiple chains can:

1. Collect all chains sharing the same `trace_id`
2. Sort events across all chains by `system_time` (HLC — causal ordering)
3. For each `cross_chain_ref` in any event, locate the referenced event in the
   referenced chain by matching `episode_id` and `event_hash`
4. Verify `event_hash == AuditEvent.hash_event_for_chain(referenced_event)`
5. If `aevum-publish` is deployed, verify the referenced chain's
   `transparency.checkpoint` via its Rekor inclusion proof (ADR-007)

### Consequences

**Good:** Backwards-compatible — `trace_id` and `span_id` already exist as
nullable first-class fields; single-agent deployments that never set them are
unaffected. A2A-compatible — `traceparent` is A2A's native propagation mechanism.
Verifiable — `event_hash` links are cryptographically checkable. No new package
required for basic correlation.

**Bad:** Cross-chain verification requires access to all involved chains — in
practice, agents must publish their chains to a shared ledger or to Rekor (ADR-007).
Without ADR-007, cross-chain links can only be verified in environments where all
chains are accessible. The `trust_domain` in `cross_chain_ref` is only meaningful
if agents use SPIFFE identity (ADR-006); without it, `trust_domain` is a
caller-asserted string.

**Residual risk:** (a) **Traceparent injection**: if the calling agent does not
inject a `traceparent` header, `trace_id` will not propagate — a deployer
responsibility Aevum cannot enforce at the protocol level. (b) **Clock skew**:
two agents' HLCs are not synchronised unless they communicate; cross-agent ordering
by `system_time` is best-effort causal ordering, not strict global ordering.
(c) **Cross-chain ref forgery**: an adversary could fabricate a `cross_chain_ref`;
mitigation is the verifier checking `event_hash` against the actual event in the
referenced chain — without chain access, the link cannot be verified, which is a
deployment gap, not a protocol gap.

## A2A compatibility note

A2A v1.0.0-rc uses OTLP spans with `traceparent` for distributed tracing. Aevum's
`trace_id` ↔ `traceparent` mapping is additive — it does not conflict with A2A's
tracing. The `cross_chain_ref` payload field is an Aevum extension that
A2A-compliant clients ignore if they do not understand it.

## Related ADRs

- ADR-001 (Single sigchain — the per-agent chain that cross_chain_ref references)
- ADR-006 (SPIFFE integration — `cross_chain_ref.trust_domain` uses SPIFFE ID)
- ADR-007 (Transparency log — external verification of cross-chain links via Rekor)
