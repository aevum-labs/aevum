# Section 11 — Complication Manifest

A **complication** is an extension to aevum-core that adds domain-specific
behaviour while operating within the kernel's governance boundaries. The
complication manifest defines the metadata, lifecycle, and obligations of
every complication.

---

## 11.1 Overview

Complications are the only sanctioned extension point. They:

- Cannot bypass the five absolute barriers (Section 7)
- Cannot call the five functions directly (they receive a restricted kernel proxy)
- Must declare their capabilities, permissions, and actor identity in a manifest
- Follow a 7-state lifecycle enforced by the kernel
- SHOULD record outcome events for irreversible actions (Section 11.6)

The term "complication" is intentional and precise. Never use: plugin,
extension, module, or addon.

---

## 11.2 Complication Manifest Fields

Every complication MUST provide a manifest at registration time. The manifest
is a Python dataclass or equivalent structured object with the following fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | str | yes | Unique identifier; lowercase, hyphens allowed |
| `version` | str | yes | SemVer string |
| `author` | str | yes | Author or org name |
| `description` | str | yes | One-sentence description |
| `actor_id` | str | yes | Identity used in audit events; MUST be unique per complication |
| `operations` | list[str] | yes | Which kernel operations this complication may invoke |
| `subject_scopes` | list[str] | yes | Which subject ID patterns this complication may access |
| `purposes` | list[str] | yes | Declared purposes for consent checking |
| `capabilities` | list[str] | no | Optional capability flags (e.g. `"webhook.send"`) |
| `max_autonomy_level` | int | yes | Maximum L1–L5 autonomy level this complication may operate at |

### 11.2.1 operations values

Valid operation strings: `"ingest"`, `"query"`, `"review"`, `"commit"`,
`"replay"`. Complications that do not list an operation MUST NOT invoke it.

### 11.2.2 max_autonomy_level

Autonomy levels follow the DeepMind taxonomy:
- L1: operator-controlled (human approves every action)
- L2: human-in-the-loop (human approves before irreversible actions)
- L3: human-on-the-loop (human can interrupt; agent proceeds by default)
- L4: human-supervised (periodic review; agent acts autonomously)
- L5: observer-only (human cannot intervene; fully autonomous)

Most complications MUST declare L1 or L2. Higher levels require explicit
operator approval via the complication approval workflow.

---

## 11.3 Lifecycle States

Every complication passes through a 7-state lifecycle:

```
REGISTERED → PENDING_APPROVAL → ACTIVE ⇄ SUSPENDED → DEPRECATED → REMOVED
                    ↓
                REJECTED
```

| State | Description |
|---|---|
| `REGISTERED` | Manifest received; awaiting admin approval |
| `PENDING_APPROVAL` | Under active admin review |
| `ACTIVE` | Approved and callable |
| `SUSPENDED` | Temporarily blocked by admin; can be resumed |
| `DEPRECATED` | Scheduled for removal; still callable |
| `REJECTED` | Approval denied; cannot be activated |
| `REMOVED` | Uninstalled; all references purged |

State transitions are recorded as sigchain events (`complication.installed`,
`complication.approved`, `complication.suspended`) — see Section 8.7.

---

## 11.4 Complication Registration

Complications are registered with the kernel via:

```python
engine.install_complication(complication_instance)
```

The kernel verifies:
1. The manifest is complete and valid
2. The `actor_id` is unique (no collision with existing complications)
3. The declared `operations` are a valid subset of the five functions
4. The `max_autonomy_level` is within operator-permitted bounds

After registration, the complication enters `REGISTERED` state. An admin
must call `engine.approve_complication(name)` to move it to `ACTIVE`.

---

## 11.5 Absolute Barrier Interactions

Complications MUST NOT:

- Attempt to bypass any absolute barrier
- Store cryptographic keys, credentials, or PII in the complication manifest
- Access `urn:aevum:provenance` directly (must use `replay()`)
- Access `urn:aevum:consent` directly (must use `add_consent_grant()`)
- Invoke the five functions using their Python implementations directly
  (must use the kernel proxy provided at `execute()` time)

Any barrier violation causes the complication to be automatically suspended
and a `barrier.triggered` event to be appended to the sigchain.

---

## 11.6 Outcome Event Obligation

When a complication executes an action that is irreversible or
affects external systems (sending a message, writing to an
external database, calling an external API), it SHOULD record
the real-world result by calling `commit()` on the kernel with
a standardised outcome event.

This closes the audit trail. Without an outcome event, the
sigchain records that an action was approved and initiated but
not whether it succeeded or failed in the real world.

### 11.6.1 Outcome Event Types

Complications MUST use the following event type format for outcome
events:

    action.outcome.ok       — action completed successfully
    action.outcome.failed   — action was attempted and failed
    action.outcome.partial  — action partially completed (use sparingly;
                              prefer ok or failed with detail in payload)

### 11.6.2 Outcome Event Payload

The payload for an outcome event MUST include:

    action_type: str
        Human-readable name of the action that was attempted.
        Example: "email.send", "database.write", "api.call"

    approval_audit_id: str
        The audit_id of the review event that authorised this action.
        Links the outcome back to the human decision in the sigchain.

    summary: str
        One-sentence human-readable description of what happened.

    detail: dict
        Structured detail. Contents are complication-defined.
        For failures MUST include an "error" key with a string value.
        MUST NOT include raw secrets, credentials, or PII.

### 11.6.3 Example

    engine.commit(
        event_type="action.outcome.ok",
        payload={
            "action_type": "email.send",
            "approval_audit_id": "urn:aevum:audit:0196f2a1-...",
            "summary": "Invoice email delivered to customer-42",
            "detail": {"recipient_hash": "sha256:...", "message_id": "msg-001"},
        },
        actor="billing-complication",
    )

### 11.6.4 When No Outcome Is Recorded

If a complication does not record an outcome event, the sigchain
will show the action as approved with no subsequent entry.
This is not a barrier violation — it is a compliance gap.
Operators SHOULD monitor for approved actions without outcome events
using the `replay` function.
