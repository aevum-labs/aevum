---
description: "Append-only, hash-chained, and cryptographically signed are three different properties. Aevum's sigchain implements all three. This page explains what each guarantees and how to verify them."
---

# What "Tamper-Evident" Actually Means for AI Agent Logs

"Tamper-evident logging" is used to describe at least three distinct properties: append-only storage (modification is prevented), hash-chained records (modification is detectable), and cryptographic signatures (modification is attributable). These are not the same thing. Implementing only the first is common; implementing all three is rare. This page explains what each property guarantees and how Aevum's sigchain implements them.

## Three properties, three guarantees

**Append-only (modification is prevented).** An append-only log refuses write operations that would modify or delete existing entries. SQLite triggers, Kafka log compaction disabled, immutable object storage — these are common implementations. The guarantee is meaningful: an attacker with write access to the storage layer through the application cannot silently alter an existing entry, because the storage layer rejects the operation. The limitation is also meaningful: an attacker with sufficient access — root on the database host, direct filesystem access, or the ability to disable the trigger — can still drop and reconstruct the database or write directly to the file. Append-only storage prevents application-layer tampering; it does not prevent infrastructure-layer tampering.

**Hash-chained (modification is detectable).** A hash-chained log includes in each entry a cryptographic hash of the preceding entry. If any entry is altered, all subsequent hashes are invalidated — the chain breaks. An auditor running `verify_sigchain()` traverses the full chain and detects the alteration at the first mismatched link. The foundational reference is Crosby and Wallach (2009), "Efficient Data Structures for Tamper-Evident Logging" — the same structure that underlies Certificate Transparency (RFC 6962) and blockchain designs. The guarantee extends beyond append-only: an attacker who has disabled the append-only trigger and modified a row must also recompute every subsequent hash consistently to avoid detection. The limitation: if all entries including their hashes are reconstructed from scratch, the forgery is undetectable without an external anchor — a published hash root or a third-party timestamp.

**Cryptographically signed (modification is attributable).** A signed log applies an asymmetric signature — Ed25519 in Aevum's case — to each entry or to the hash-chain root. An external party holding the public key can verify that each entry was produced by the private key holder and that it has not been altered since signing. Combined with a public transparency log or an external timestamp anchor, signatures make forgery detectable even if the attacker controls all local storage: reconstructing a convincing chain requires the private key, which the attacker does not have. This property also provides attribution: if the private key is controlled by the kernel and is not accessible to application code, a signed entry is evidence that the kernel itself produced it, not an application-layer process that might have been compromised.

## Aevum's sigchain — all three properties

Aevum implements all three properties in its episodic ledger. It is important not to overstate what each provides.

**Append-only:** the episodic ledger uses SQLite triggers that prevent UPDATE and DELETE operations on ledger rows. This holds against application-layer attacks and against any code that accesses the database through Aevum's API. A direct edit to the SQLite file bypasses the trigger — the append-only property at the storage layer requires that the SQLite file itself be protected by filesystem permissions or immutable storage.

**Hash-chained:** each `AuditEvent` includes `previous_hash` — the SHA3-256 digest of the preceding event's canonical representation. `engine.verify_sigchain()` recomputes the full chain from the genesis entry and returns `False` if any hash does not match. Any modification to any field in any entry — including metadata fields like timestamps, actor identifiers, or event types — produces a hash mismatch that is detected on the next verification pass.

**Ed25519 signed:** each event is signed with the kernel's Ed25519 private key before being appended to the ledger. The public key is available for external verification.

```python
from aevum.core import Engine
from aevum.core.consent.models import ConsentGrant

engine = Engine()

engine.add_consent_grant(ConsentGrant(
    grant_id="demo-grant-001",
    subject_id="user-1",
    grantee_id="demo-agent",
    operations=["ingest", "query"],
    purpose="demo",
    classification_max=0,
    granted_at="2026-01-01T00:00:00Z",
    expires_at="2030-01-01T00:00:00Z",
))

# Write several events
for i in range(5):
    engine.ingest(
        data={"event_number": i},
        provenance={
            "source_id": "demo",
            "chain_of_custody": ["demo"],
            "classification": 0,
        },
        purpose="demo",
        subject_id="user-1",
        actor="demo-agent",
    )

# Verify the chain — checks every hash link from genesis
intact = engine.verify_sigchain()
print(f"Chain intact: {intact}")  # True

# Inspect the ledger — each entry includes previous_hash
entries = engine.get_ledger_entries()
for entry in entries[-3:]:  # last three entries
    print(f"event: {entry['event_type']:25} hash: {entry.get('hash', 'N/A')[:16]}...")
```

## What verify_sigchain() actually checks

`verify_sigchain()` traverses every entry in the episodic ledger from the genesis entry to the current tip. For each consecutive pair of entries, it recomputes the SHA3-256 hash of the earlier entry's canonical representation and checks it against the `previous_hash` field stored in the later entry. If any entry has been modified — including metadata fields like timestamps, actor identifiers, or event types — the recomputed hash will not match the stored `previous_hash`, and `verify_sigchain()` returns `False`. The method returns `True` only if every link in the chain from genesis to the current tip is valid. This means a single altered entry is detected regardless of its position in the chain, and the detection is guaranteed to fire on the next verification pass after the alteration occurs.

## Compliance relevance

| Standard / Regulation | Relevant requirement | How Aevum satisfies it |
|------------------------|----------------------|------------------------|
| EU AI Act Article 12 | Automatic recording with traceability | Append-only episodic ledger; every call audited |
| EU AI Act Article 15 | Accuracy and robustness | Hash-chaining detects any post-write alteration |
| ISO/IEC 42001 | AI management system audit trail | Sigchain provides immutable governance record |
| SOC 2 PI1.2 | Processing integrity — complete and accurate | Ed25519 signatures on every entry |
| OWASP ASI06 | Memory and context poisoning | Provenance chain on every ingest |

Aevum provides the technical control. Compliance assessors determine whether the control satisfies specific regulatory requirements in your jurisdiction and risk context.

## See also

- [The Sigchain](../learn/architecture.md#the-sigchain)
- [Audit Trails and Article 12](audit-trails.md)
- [Audit Events reference](../reference/api.md#auditevent)
