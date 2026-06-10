---
description: "Aevum terminology reference — definitions for all core concepts
including sigchain, governed membrane, complication, consent grant, and more."
---

# Glossary

Hover tooltips for these terms appear throughout the documentation
wherever the term is used in prose.

**unconditional barrier**
: An unconditional, hardcoded enforcement check in `barriers.py`.
  Cannot be disabled by configuration, policy, or administrator override.
  Aevum has five: crisis detection (B1), classification ceiling (B2),
  consent (B3), audit immutability (B4), and provenance (B5).

**AuditEvent**
: An 18-field signed record in the episodic ledger. Every engine call
  produces exactly one AuditEvent.

**audit_id**
: A `urn:aevum:audit:<uuid7>` URI that uniquely identifies one `AuditEvent`
  in the episodic ledger. Returned in every `OutputEnvelope.audit_id` field,
  even on error. Used as the key for `replay(audit_id=...)` calls.

**classification ceiling**
: The maximum classification level an actor may access. Enforced by
  Barrier 2 on every `query` call: if any requested subject's classification
  exceeds this level, the query is blocked entirely (`error_code="classification_blocked"`).

**complication**
: A vetted extension mechanism. Not a plugin — complications require
  explicit approval and pass canary tests before activation.

**ConsentGrant**
: A scoped, purpose-bound, time-limited access authorization. Required
  for `ingest`, `query`, and `replay` operations.

**episode**
: A group of related AuditEvents representing one complete agent workflow,
  identified by a shared `episode_id`.

**episode_id**
: A UUID that groups related `AuditEvent` records into a single logical
  workflow. Set by the caller on the first call in a workflow; subsequent
  calls in the same workflow reuse the same `episode_id` to link their
  ledger entries.

**episodic ledger**
: The append-only, Ed25519-signed, SHA3-256 hash-chained record of all
  engine events. Stored at `urn:aevum:provenance`.

**governed membrane**
: The enforcement layer through which all data passes on ingest and query.
  Barriers 3 (consent) and 5 (provenance) fire here unconditionally.

**knowledge graph**
: The working graph of entities and relationships. Stored at
  `urn:aevum:knowledge`. Mutable via `ingest`.

**Hybrid Logical Clock (HLC)**
: A timestamping scheme that combines a physical wall-clock component with a
  logical counter. Aevum uses HLC to produce monotonic, causally ordered
  timestamps for `AuditEvent` records across distributed nodes — without
  requiring clock synchronization.

**OR-Set CRDT**
: Observed-Remove Set, a conflict-free replicated data type. Used for the
  consent ledger to enable immediate, consistent revocation.

**OutputEnvelope**
: The standard return type for all five functions. Fields: `status`,
  `audit_id`, `data`, `confidence`, `provenance`, `warnings`.

**prior hash**
: The SHA3-256 digest of the preceding `AuditEvent`'s canonical
  representation. Stored in each event as `prior_hash`. Any modification
  to a past event invalidates `prior_hash` in the next entry, making
  the break detectable by `engine.verify_sigchain()`.

**provenance**
: A record of where data came from and who handled it. Aevum requires
  provenance on every `ingest()` call — a `source_id` and `chain_of_custody`
  list. Barrier 5 (Provenance) blocks ingestion if provenance is absent
  or incomplete.

**replay**
: The `replay(audit_id=...)` function. Reconstructs any past decision
  exactly as it occurred, using the episodic ledger entry identified by
  `audit_id`. Replay is deterministic: the same `audit_id` always returns
  the same payload. Contrast with re-execution (running the operation again
  with current data), which may produce different results.

**sigchain**
: The Ed25519-signed, SHA3-256 hash-chained episodic ledger. Every entry
  links to the previous via `prior_hash`. Alteration is immediately
  detectable via `verify_sigchain()`.

**subject**
: The entity whose data an operation concerns, identified by `subject_id`.
  Consent grants are scoped to a subject: a grant for `subject_id="user-123"`
  does not authorize access to `subject_id="user-456"`. In GDPR terms, the
  subject is the data subject whose personal data is being processed.
