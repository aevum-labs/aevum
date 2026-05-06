# ADR-003: OR-Set CRDT for consent model

Date: 2026-05-06
Status: Accepted
Deciders: Aevum Labs
Confidence: High

## Context and Problem Statement

AI agent consent must be revocable immediately — not eventually. In a
distributed environment where multiple replicas serve an agent, a revocation
must propagate before the next operation, not after. What data structure
satisfies immediate-revocation semantics without a central coordinator?

## Decision Drivers

- GDPR Art. 7(3): withdrawal of consent must be as easy as giving it, and
  the data subject must be able to withdraw at any time
- GDPR Art. 17: right to erasure — withdrawal must halt processing immediately
- California CCPA and Colorado AI Act impose similar consent withdrawal obligations
- OR-Set semantics: "add wins" until explicit remove — models grant/revoke naturally

## Considered Options

1. **OR-Set CRDT** (this decision)
2. Last-Write-Wins register
3. Centralised revocation server

## Decision Outcome

Option 1. An OR-Set (Observed-Remove Set) treats each grant as a unique tagged
element. A revocation removes a specific tagged grant. If two concurrent grants
exist, both must be revoked independently — "add wins" until explicitly removed.

This models the real-world consent lifecycle: a subject may grant purpose A
and purpose B independently; revoking purpose A should not affect purpose B.

### Consequences

**Good:** No coordinator required; revocations converge across replicas;
semantics match GDPR Art. 7(3) withdrawal requirements; subject can have
multiple concurrent purpose-scoped grants, each independently revocable.

**Bad:** If the same grant is added twice concurrently (network partition),
both must be explicitly revoked. Mitigation: grant_id is globally unique
(UUID v7) so duplicate detection is trivial.

**Residual risk:** CRDT merge happens in memory — a crash-restart scenario
may lose in-flight grants if the consent store is ephemeral. Mitigation:
persistent consent store (PostgresConsentLedger) is required for production.

## Related ADRs

- ADR-001 (single chain — consent events are recorded in the sigchain)
