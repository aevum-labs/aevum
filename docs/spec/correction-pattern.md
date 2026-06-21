# Correction Pattern — Append, Never Mutate

This document specifies how a previously-committed fact in the episodic
ledger is corrected. It complements the append-only invariant (Barrier 4 —
Audit Immutability, I1-APPEND_ONLY): the ledger has no UPDATE or DELETE
operation, so a correction can never take the form of changing an existing
entry. It must instead be a new entry.

---

## The pattern

A correction is a **new appended event** that references the superseded
entry's `entry_hash` (the value `AuditEvent.hash_event_for_chain(event)`
computed over the original entry's signing fields — the same value exposed
as `sigchain_entry_hash` on receipts). The original entry is never deleted,
mutated, or removed from the chain.

Rules:

1. **The original entry is untouched.** Its `prior_hash`, `sequence`,
   `signature`, and `payload` remain exactly as signed. This is structurally
   enforced — `Sigchain`/`InMemoryLedger` raise `BarrierViolationError` on
   any delete or overwrite attempt (Barrier 4).

2. **The correction is a new event**, appended in the normal chain position
   (next available `sequence`), signed like any other entry. Its
   `event_type` uses the domain-appropriate dotted namespace with a
   `.correction` suffix (e.g. `ingest.correction`, `commit.correction`) —
   no schema change is required, since `event_type` is an open dotted
   namespace, not a closed enum (`aevum-event-v1.json`).

3. **The correction's payload carries the reference and the new facts:**

   | Field | Meaning |
   |---|---|
   | `corrects_entry_hash` | The superseded entry's `entry_hash` (hex SHA3-256) |
   | `correction_reason` | Human-readable reason for the correction |
   | `corrected_fields` | The specific fields being corrected, with their new values |

   `causation_id` is deliberately **not** reused for this reference: it
   already means "the event that caused this one" (event-sourcing
   causality), which is a different relationship than "the entry this one
   supersedes." Conflating the two would make `causation_id` ambiguous for
   every other event type that uses it.

4. **Both entries stay visible, always.** Evidentiary integrity requires
   that nothing about the original's existence or content is hidden once a
   correction is appended — only that readers know which is current.
   Hiding the original would defeat the purpose of an append-only ledger:
   the audit trail must show that the original was recorded, and when and
   why it was corrected, not silently produce only the corrected view as if
   it had always been there.

5. **Readers resolve "current truth" by scanning forward.** A reader
   building working context (the `query`/NAVIGATE path) for an entry should
   look for any later `.correction` event whose `corrects_entry_hash`
   matches that entry's `entry_hash`, and surface the correction's
   `corrected_fields` as the current value. If a correction has itself been
   corrected, the most recent (highest-`sequence`) correction in the chain
   referencing the same `entry_hash` (directly, or transitively via a chain
   of corrections) is current.

6. **`replay` is unaffected by later corrections — by design.** `replay`'s
   guarantee is to faithfully reconstruct a *past* decision as it stood at
   the time it was made. A decision made before a correction was appended
   must replay using the original, uncorrected fact — that is what "as it
   stood" means. Corrections change what `query` surfaces as *current*
   going forward; they do not retroactively change what `replay`
   reconstructs about what was known *then*. Both behaviors are required by
   the same evidentiary-integrity principle: the record of what was known
   when must not be rewritten by later knowledge.

## Relationship to the GDPR tombstone pattern

The GDPR Article 17 erasure tombstone (`docs/compliance/gdpr-article-17.md`)
is a sibling append-only pattern, not the same one. Both never mutate the
original entry; they differ in intent:

| | Tombstone (erasure) | Correction |
|---|---|---|
| Triggered by | Right-to-erasure request | A fact was wrong / incomplete |
| Original payload | Off-chain data is deleted; on-chain payload was already non-identifying | On-chain payload is retained in full |
| New event | Optional `GDPR.erasure.complete` record | Required `*.correction` event |
| Original entry after | Still chain-valid; referenced data is gone | Still chain-valid; superseded but intact |

A correction never deletes data. A tombstone never carries a "corrected"
value — there is nothing left to correct, because the personal data was
removed, not amended.

## Worked example

An `ingest.accepted` entry records a subject's stated jurisdiction
incorrectly. The mistake is discovered later and corrected.

**Original entry** (sequence 41):

```json
{
  "event_id": "01927e4a-0000-7000-8000-000000000041",
  "sequence": 41,
  "event_type": "ingest.accepted",
  "actor": "membrane/ingest-api",
  "payload": {
    "subject_id": "subj-8821",
    "jurisdiction": "US-CA"
  },
  "payload_hash": "7f3a...c1",
  "prior_hash": "9b2e...44",
  "signature": "MEUCIQ...",
  "signer_key_id": "ed25519:k1"
}
```

`entry_hash` for this entry (computed by any verifier from the signing
fields above): `e4d1...09` (illustrative — the real value is the hex SHA3-256
digest of the canonical signing-field bytes).

**Correction entry** (sequence 57, appended later — note the chain has
moved on; nothing about entry 41 changed):

```json
{
  "event_id": "01927e4a-0000-7000-8000-000000000057",
  "sequence": 57,
  "event_type": "ingest.correction",
  "actor": "ops/data-quality-review",
  "payload": {
    "corrects_entry_hash": "e4d1...09",
    "correction_reason": "Subject's jurisdiction was transcribed incorrectly at intake; corrected per subject's account records.",
    "corrected_fields": {
      "jurisdiction": "US-NY"
    }
  },
  "payload_hash": "a08c...77",
  "prior_hash": "<hash of entry 56>",
  "signature": "MEUCIQ...",
  "signer_key_id": "ed25519:k1"
}
```

**Reader behavior:**

- `query` (NAVIGATE) building working context for subject `subj-8821` after
  sequence 57 surfaces `jurisdiction: "US-NY"` — the corrected value — while
  still being able to show, on request, that the original recorded value
  was `"US-CA"` and when/why it was corrected (both entries are queryable).
- `replay` of any decision that consumed entry 41's context **before**
  sequence 57 was appended faithfully reconstructs that decision using
  `jurisdiction: "US-CA"` — the value that was actually on record at that
  time — even though it is now known to be wrong. This is correct behavior,
  not a bug: replay answers "what did the system know when it decided this,"
  not "what do we know now."

## Related

- Barrier 4 — Audit Immutability (`packages/aevum-core/src/aevum/core/barriers.py`)
- `aevum.core.audit.event.AuditEvent.hash_event_for_chain` — `entry_hash` computation
- `docs/spec/aevum-event-v1.md` — event schema, `event_type` namespace rules
- `docs/compliance/gdpr-article-17.md` — the sibling tombstone (erasure) pattern
- `CHANGELOG.md` — `[1.0.0]` section, correction-pattern design closed
