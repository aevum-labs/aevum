---
description: "Aevum terminology reference — definitions for all core concepts
including sigchain, governed membrane, complication, consent grant, and more."
---

# Glossary

Hover tooltips for these terms appear throughout the documentation
wherever the term is used in prose.

**absolute barrier**
: An unconditional, hardcoded enforcement check in `barriers.py`.
  Cannot be disabled by configuration, policy, or administrator override.

**AuditEvent**
: An 18-field signed record in the episodic ledger. Every engine call
  produces exactly one AuditEvent.

**classification ceiling**
: The maximum classification level an actor may access, enforced by
  Barrier 2 on every `query` call.

**complication**
: A vetted extension mechanism. Not a plugin — complications require
  explicit approval and pass canary tests before activation.

**ConsentGrant**
: A scoped, purpose-bound, time-limited access authorization. Required
  for `ingest`, `query`, and `replay` operations.

**episode**
: A group of related AuditEvents representing one complete agent workflow,
  identified by a shared `episode_id`.

**episodic ledger**
: The append-only, Ed25519-signed, SHA3-256 hash-chained record of all
  engine events. Stored at `urn:aevum:provenance`.

**governed membrane**
: The enforcement layer through which all data passes on ingest and query.
  Barriers 3 (consent) and 5 (provenance) fire here unconditionally.

**knowledge graph**
: The working graph of entities and relationships. Stored at
  `urn:aevum:knowledge`. Mutable via `ingest`.

**OR-Set CRDT**
: Observed-Remove Set, a conflict-free replicated data type. Used for the
  consent ledger to enable immediate, consistent revocation.

**OutputEnvelope**
: The standard return type for all five functions. Fields: `status`,
  `audit_id`, `data`, `confidence`, `provenance`, `warnings`.

**sigchain**
: The Ed25519-signed, SHA3-256 hash-chained episodic ledger. Every entry
  links to the previous via `prior_hash`. Alteration is immediately
  detectable via `verify_sigchain()`.
