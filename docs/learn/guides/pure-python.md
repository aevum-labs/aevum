---
description: "End-to-end Aevum integration guide for pure Python applications — without AEVUM_DEV=1."
---

# Pure Python Integration Guide

This guide walks through a complete Aevum integration for a Python application.
It uses the production path (no `AEVUM_DEV=1`) to show what a real deployment
looks like: explicit consent grants, real provenance, and sigchain verification.

If you are just getting started, read the [Quickstart](/getting-started/quickstart/) first.

---

## What we are building

A Python function that:

1. Grants a support agent consent to read a user's ticket data
2. Ingests a ticket through the governed membrane (signed, chained)
3. Queries the data with consent verification
4. Replays the exact state at ingest time
5. Verifies the sigchain is intact

---

## Install

```bash
pip install aevum-core
```

For Cedar-based policy enforcement (recommended for production):

```bash
pip install "aevum-core[cedar]"
```

---

## Complete example

```python
"""
Pure Python integration — no AEVUM_DEV=1.

Demonstrates: consent grants → ingest → query → replay → verify.
"""
from aevum.core import Engine
from aevum.core.consent.models import ConsentGrant

# ── 1. Create the engine ──────────────────────────────────────────────────────
# No AEVUM_DEV=1. Engine uses InMemoryLedger (dev/demo) and attempts to load
# CedarPolicyEngine. Falls back to NullPolicyEngine with a warning if Cedar is
# not installed.
engine = Engine()

# ── 2. Grant consent ──────────────────────────────────────────────────────────
# In production: load grants from your database, not hardcoded here.
# Grant is per-subject, per-purpose, time-bounded.
engine.add_consent_grant(ConsentGrant(
    grant_id="grant-alice-support-2026",
    subject_id="alice",
    grantee_id="support-agent",
    operations=["ingest", "query"],
    purpose="support-ticket-resolution",
    classification_max=0,
    granted_at="2026-01-01T00:00:00Z",
    expires_at="2027-01-01T00:00:00Z",
))

# ── 3. Ingest — write through the governed membrane ───────────────────────────
# Every ingest call:
#   - Checks Barrier 3 (consent) — fails with consent_required if not granted
#   - Checks Barrier 5 (provenance) — requires source_id
#   - Signs the event with Ed25519
#   - Chains it with SHA3-256 (SHA3-256(prev_event_signing_fields))
result = engine.ingest(
    data={"ticket": "T-001", "description": "Cannot log in to the portal"},
    provenance={
        "source_id": "support-portal",
        "chain_of_custody": ["support-portal"],
        "classification": 0,
    },
    purpose="support-ticket-resolution",
    subject_id="alice",
    actor="support-agent",
)

print("status: ", result.status)    # ok
print("audit_id:", result.audit_id) # urn:aevum:audit:0196...

# ── 4. Query — read with consent verification ─────────────────────────────────
# query() checks Barrier 3 again: returns results only if consent is active.
q = engine.query(
    purpose="support-ticket-resolution",
    subject_ids=["alice"],
    actor="support-agent",
)
print("subjects:", list(q.data["results"].keys()))  # ['alice']

# ── 5. Replay — reconstruct exact past state ──────────────────────────────────
# replay() returns the exact payload from the ingested event, unchanged.
# No summarisation. No inference. Deterministic reconstruction.
r = engine.replay(audit_id=result.audit_id, actor="support-agent")
assert r.data["replayed_payload"]["ticket"] == "T-001"
print("replayed:", r.data["replayed_payload"]["description"])

# ── 6. Verify sigchain ────────────────────────────────────────────────────────
# verify_sigchain() walks every event from genesis, checking both the SHA3-256
# chain (prior_hash) and the Ed25519 signature on each event.
ok = engine.verify_sigchain()
print("chain intact:", ok)  # True
```

---

## Consent errors

Try removing the `add_consent_grant()` call:

```python
# engine.add_consent_grant(...)  # commented out

result = engine.ingest(...)
print(result.status)                        # error
print(result.data["error_code"])            # consent_required
print(result.data["error_detail"])          # No active consent grant for ...
```

Barrier 3 fires before any data is written. Nothing reaches the sigchain.

---

## Provenance errors

Try removing `source_id` from provenance:

```python
result = engine.ingest(
    data={"ticket": "T-002", ...},
    provenance={},               # no source_id
    ...
)
print(result.status)                    # error
print(result.data["error_code"])        # provenance_required
```

Barrier 5 fires. No data written.

---

## Persistent storage (production)

For real deployments, replace the in-memory store:

```python
from aevum.store.oxigraph import OxigraphStore

engine = Engine(
    graph_store=OxigraphStore(path="/var/lib/aevum/graph"),
)
```

The sigchain persists across process restarts. The `session.start` event
links to the previous session's last event via `causation_id`.

---

## Episode grouping

Group related operations into a named episode for forensic replay:

```python
import uuid
episode = str(uuid.uuid4())

result = engine.ingest(..., episode_id=episode, ...)
q = engine.query(..., episode_id=episode, ...)
```

All events with the same `episode_id` are queryable as a unit for replay
and compliance reporting.

---

## Next steps

- [Dev to Production checklist](https://github.com/aevum-labs/aevum/blob/main/docs/learn/dev-to-production.md)
- [LangChain guide](/learn/guides/langchain/)
- [Architecture](/learn/architecture/)
