---
description: "Complete API reference for Aevum: Engine, OutputEnvelope,
ConsentGrant, AuditEvent, and all method signatures."
---

# API Reference

## Engine

The main entry point for all Aevum operations.

`Engine` wires together the episodic ledger, consent ledger, graph store,
policy bridge, complication registry, and the five governed functions.

::: aevum.core.engine.Engine
    options:
      show_source: false
      members:
        - ingest
        - query
        - review
        - commit
        - replay
        - add_consent_grant
        - revoke_consent_grant
        - verify_sigchain
        - install_complication
        - approve_complication
        - suspend_complication
        - resume_complication
        - list_complications
        - complication_state
        - register_webhook
        - deregister_webhook
        - create_review
        - get_ledger_entries
        - ledger_count

## OutputEnvelope

Every function returns exactly one `OutputEnvelope`. No exceptions.

Always check `result.status` before accessing `result.data`. The `audit_id`
is always present, even on error.

::: aevum.core.envelope.models.OutputEnvelope

::: aevum.core.envelope.models.ProvenanceRecord

::: aevum.core.envelope.models.ReviewContext

::: aevum.core.envelope.models.UncertaintyAnnotation

::: aevum.core.envelope.models.SourceHealthSummary

::: aevum.core.envelope.models.ReasoningTrace

::: aevum.core.envelope.models.ReasoningStep

## ConsentGrant

The unit of permission. Every `ingest`, `query`, and `replay` operation
requires an active, non-expired `ConsentGrant` for the subject and operation.

Valid operations: `"ingest"`, `"query"`, `"replay"`, `"export"`

::: aevum.core.consent.models.ConsentGrant

## AuditEvent

The 18-field immutable episodic ledger entry. Every operation appends
exactly one `AuditEvent` to `urn:aevum:provenance`. This is the information
stored in each chain entry — the raw material for deterministic replay.

::: aevum.core.audit.event.AuditEvent

## See also

- [Architecture](/learn/architecture/) — how these types are used
- [CLI Reference](/reference/cli/)
