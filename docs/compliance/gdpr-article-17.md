# GDPR Article 17 — Right to Erasure: Integration Pattern

**Status:** Normative  
**Applies to:** All Aevum deployments that process personal data of EU/EEA data subjects

---

## The Tension: Append-Only Sigchains vs the Right to Erasure

Aevum's episodic ledger is **append-only by design**. Every `commit` operation
appends a signed, chained `AuditEvent` to the sigchain. Barrier 4 (Audit Seal)
makes deletion or mutation of ledger entries a hardcoded unconditional barrier —
no policy override is possible.

GDPR Article 17 grants data subjects the right to erasure ("right to be
forgotten") of their personal data. A naïve implementation that stores raw
personal data inside ledger payloads creates an irresolvable conflict: the data
cannot be deleted without breaking the cryptographic chain.

**Aevum resolves this tension at the architectural level.** The episodic ledger
is not permitted to store raw personal data. The Cedar policy `gdpr_pii.cedar`
enforces this unconditionally.

---

## The Solution: Off-Chain Data + On-Chain Hash Pointer + Crypto-Shredding

The pattern has three components:

### 1. Off-Chain Personal Data Store

All personal data (PII, special-category data, biometrics, etc.) is stored in a
**separate, erasable datastore** (database, object store, encrypted vault) —
never in the sigchain payload.

```
[Personal Data Store]          [Aevum Episodic Ledger]
   subject_id: "s-123"         AuditEvent {
   name: "Alice"          →       payload: {
   email: "alice@..."                 subject_id: "s-123",
   ...                                data_hash: "sha256:abc123...",
                                      key_id: "kek-s-123-2026-01",
                                  }
                                }
```

The sigchain stores only:

- A **subject identifier** (pseudonymous, not directly identifying)
- The **SHA-256 hash** of the personal data at ingestion time
- The **key ID** used to encrypt the personal data

### 2. Per-Subject Encryption Key Derivation

Personal data is encrypted with a **per-subject, per-period key** derived from a
Key Encryption Key (KEK). The KEK is stored in a secrets manager (e.g.,
HashiCorp Vault, AWS KMS).

```python
import os, hashlib, secrets

def derive_subject_key(kek: bytes, subject_id: str, period: str) -> bytes:
    """Derive a deterministic 256-bit encryption key for a subject+period."""
    material = f"aevum:subject:{subject_id}:period:{period}".encode()
    return hashlib.blake2b(material, key=kek, digest_size=32).digest()

def generate_subject_kek(subject_id: str) -> bytes:
    """Generate a fresh random KEK for a new subject. Store in secrets manager."""
    return secrets.token_bytes(32)
```

The key ID stored in the sigchain payload (`key_id`) encodes the subject and
period (e.g., `kek-s-123-2026-01`) but does not contain the key material.

### 3. Erasure via Crypto-Shredding

When a subject invokes Article 17, the erasure procedure is:

1. **Delete** the subject's personal data from the off-chain datastore.
2. **Delete** the subject's KEK from the secrets manager (crypto-shredding).
3. The sigchain entries remain intact — they now contain an opaque hash pointer
   to data that no longer exists and cannot be re-derived (the KEK is gone).

The on-chain hash (`data_hash`) cannot be reversed to recover personal data
without both the original data AND the encryption key. With the KEK deleted,
the hash is cryptographically inert.

```python
def erase_subject(subject_id: str, secrets_manager: SecretsManager,
                  personal_data_store: DataStore) -> None:
    """
    Execute GDPR Article 17 erasure for subject_id.
    Crypto-shredding: delete KEK, then delete raw data.
    """
    # 1. Delete KEK — makes all derived keys irrecoverable
    secrets_manager.delete(f"kek/{subject_id}")

    # 2. Delete raw personal data
    personal_data_store.delete_subject(subject_id)

    # Sigchain entries are NOT touched — they remain valid chain links
    # but reference data that is now cryptographically inaccessible.
```

---

## Aevum's Supported Integration Pattern

**Only the pattern described above is supported.** Specifically:

| Requirement | Status |
|---|---|
| Raw PII in sigchain payloads | **Forbidden** (enforced by `gdpr_pii.cedar`) |
| Subject identifier in payload | Permitted (pseudonymous, non-identifying alone) |
| Hash pointer in payload | Permitted |
| Key ID reference in payload | Permitted |
| Off-chain personal data store | Required (operator responsibility) |
| Per-subject KEK in secrets manager | Required (operator responsibility) |
| Crypto-shredding on Article 17 request | Required (operator responsibility) |

Aevum enforces the first row via Cedar policy. Rows 2–7 are architectural
requirements that operators must implement in their integration layer.

### Cedar Policy Enforcement

The Cedar policy `packages/aevum-core/src/aevum/core/policies/gdpr_pii.cedar`
unconditionally blocks any `relate_graph_write` action where
`context.contains_raw_pii == true`:

```cedar
forbid (
  principal,
  action == Action::"relate_graph_write",
  resource
) when {
  context.contains_raw_pii == true
};
```

Callers of `ingest()` must set `context.contains_raw_pii` in their Cedar
context. If the flag is absent (defaults to `false`), the policy does not fire.
Operators **must** set this flag correctly at their integration boundary.

---

## Verifying the Pattern

```bash
# Validate the Cedar policy loads correctly
uv run python -c "
from aevum.core.policy.cedar_engine import CedarPolicyEngine
e = CedarPolicyEngine.default()
print('OK')
"
```

---

## References

- GDPR Article 17: Right to erasure ('right to be forgotten')
- Aevum Frozen Invariant 5: Append-only property of the episodic ledger
- Aevum Frozen Invariant 7: Provenance as precondition
- Aevum Barrier 4 (`barriers.cedar`): Audit Seal — no deletions or mutations
- `packages/aevum-core/src/aevum/core/policies/gdpr_pii.cedar`
