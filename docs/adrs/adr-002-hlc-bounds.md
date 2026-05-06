# ADR-002: Hybrid Logical Clock for event ordering with documented bounds

Date: 2026-05-06
Status: Accepted
Deciders: Aevum Labs
Confidence: High

## Context and Problem Statement

Events in Aevum must be totally ordered for replay() to reconstruct context
faithfully. Physical clocks are unreliable (NTP corrections, VM clock skew).
Logical clocks (Lamport) are not human-readable. What ordering mechanism
satisfies both causal ordering correctness and human-interpretable timestamps?

## Decision Drivers

- Auditors expect timestamps that look like wall-clock time
- replay() requires causal ordering to be deterministic and reproducible
- NTP corrections must not break the ordering guarantee
- MiFID II RTS 25 requires UTC-traceable timestamps — but this is a *separate*
  concern from causal ordering (addressed in deployment docs, not kernel)

## Considered Options

1. **Hybrid Logical Clock (HLC)** — Kulkarni et al.
2. Physical clock (system time only)
3. Lamport logical clock (no wall-clock component)

## Decision Outcome

Option 1, with the following documented invariants:

**Correctness invariants (must hold in every implementation):**
- `_sequence` (HLC counter) resets to 0 when physical time advances past
  the last known HLC — ensuring monotonicity after NTP step-back
- A single process-wide mutex guards all HLC reads/writes (see Sigchain._lock)
- On Engine restart with a persistent backend, the HLC must be initialized
  from the max(persisted_hlc, current_physical) — not from 0

**NOT a substitute for:** RFC 3161 trusted timestamps or UTC-traceable physical
clocks for legal evidence under eIDAS, MiFID II RTS 25, or FINRA CAT.
Those contexts require an external time attestation in addition to HLC ordering.

**Counter overflow policy:** The HLC counter is a 64-bit integer. At
nanosecond resolution with a maximum physical clock frequency of 1GHz,
overflow requires 584 years of monotonic operation. No mitigation needed.

### Consequences

**Good:** Monotonic ordering survives NTP corrections; timestamps look like
wall-clock time; replay() is deterministic; single-process correctness without
distributed coordination.

**Bad:** HLC values are NOT legally defensible wall-clock timestamps without
RFC 3161 attestation.

## Related ADRs

- ADR-001 (single chain)
- ADR-004 (external signer — addresses the wall-clock trust gap)
