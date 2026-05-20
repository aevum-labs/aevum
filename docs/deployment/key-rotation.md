# Signing Key Rotation — Aevum Deployment Guide

**Audience:** Operators running Aevum with an external signer (VaultTransitSigner or KMS).  
**Scope:** Planned rotation and emergency rotation of the Ed25519 signing key.  
**Applies to:** aevum-core v0.6.0+ (schema_version "1.1", key_scheme "ed25519").

---

## Background

Every entry in the episodic ledger is Ed25519-signed with a key whose identity is
recorded in `signer_key_id`. The sigchain is a hash chain — each event's `prior_hash`
is the SHA3-256 digest of the previous event's signed fields (including `key_scheme`
from schema_version "1.1" onward). Chain integrity does **not** depend on every event
sharing the same signing key. A key change is visible as a `signer_key_id` transition
in the ledger, and `verify_chain()` rejects any entry whose signature does not match
the public key at verification time.

**Tamper evidence vs. tamper prevention:**

| Signer | Tamper evident | Tamper resistant |
|---|---|---|
| InProcessSigner | Yes (hash chain) | No (key in process memory) |
| VaultTransitSigner / KMS | Yes | Yes (key in HSM boundary) |

For FDA §11.10(e) / EU AI Act Art. 12 compliance, use an external signer.

---

## Key Scheme Field (Phase C-1)

From v0.6.0, every new ledger entry carries:

```json
{
  "schema_version": "1.1",
  "key_scheme": "ed25519"
}
```

`key_scheme` is included in both the signed fields and the chain hash for
schema_version "1.1" entries. It commits the signing algorithm to the chain, binding
the `signer_key_id` rotation record to a declared algorithm. Future value:
`"ed25519+ml-dsa-65"` (hybrid post-quantum — not yet enabled).

---

## Planned Key Rotation

Use this procedure when rotating proactively (scheduled rotation, key expiry, or
Vault key version upgrade).

### Prerequisites

- You have write access to Vault (or your KMS).
- The running Aevum engine uses an external signer (VaultTransitSigner or equivalent).
- You have a database backup or Rekor checkpoint for the current chain tail.

### Step 1 — Record the current chain tail

Before rotating, capture the current chain checkpoint. This is the
**continuity proof**: after rotation, the new key's first entry chains off this
exact hash.

```python
from aevum.core.audit.sigchain import Sigchain

# Obtain the current Sigchain instance from your Engine
chain: Sigchain = engine._sigchain  # internal access for ops tooling

sequence, prior_hash = chain.checkpoint()
print(f"Chain tail: sequence={sequence}, prior_hash={prior_hash}")
# Record this in your ops log before proceeding.
```

Alternatively, query the last ledger entry:

```python
last_event = engine._ledger.all_events()[-1]
print(f"Last event: {last_event.event_id}, seq={last_event.sequence}")
print(f"Chain tail hash: {last_event.prior_hash}")
```

### Step 2 — Create the new key in Vault

```bash
# Vault Transit: rotate to a new key version
vault write -f transit/keys/aevum-signer/rotate

# Confirm the new version
vault read transit/keys/aevum-signer
# Note the "latest_version" field — this is the new signer_key_id suffix.
```

For AWS KMS: schedule key rotation via the console or CLI; the KMS ARN remains
stable but the backing key material rotates.

### Step 3 — Construct the new Signer and Sigchain

```python
from aevum.core.audit.sigchain import Sigchain

# Wire the new signer pointing to the new Vault key version
new_signer = VaultTransitSigner(
    vault_url="https://vault.example.com",
    key_name="aevum-signer",
    key_version=new_version,  # from Step 2
)

# Resume from the recorded chain tail (continuity proof)
new_chain = Sigchain(
    signer=new_signer,
    initial_sequence=sequence,
    initial_prior_hash=prior_hash,
)
```

The new chain's first `new_event()` call will:
- Set `signer_key_id` to the new Vault key identifier.
- Set `prior_hash` to the tail captured in Step 1.
- Sign with the new key.
- Hash the signed fields into the next `prior_hash`.

This proves continuity: the chain hash at the rotation boundary is signed by the
**old** key and chained by the **new** key. No gap is introduced.

### Step 4 — Emit a `key.rotated` audit event

Immediately after the first event from the new signer, commit a rotation notice:

```python
engine.commit(
    event_type="key.rotated",
    payload={
        "previous_key_id": old_signer_key_id,
        "new_key_id": new_signer.key_id,
        "rotation_reason": "scheduled",
        "operator": "ops@example.com",
    },
    actor="ops-rotation-script",
)
```

This creates a permanent, signed record of the rotation in the episodic ledger.

### Step 5 — Verify the chain across the rotation boundary

```python
all_events = engine._ledger.all_events()
ok = new_chain.verify_chain(all_events)
assert ok, "Chain verification failed after key rotation"
print("Chain verified across rotation boundary ✓")
```

**Note:** `verify_chain()` verifies each entry against the public key of the
`Sigchain`'s current signer. For a multi-key chain, you must call `verify_chain()`
twice: once with the old signer for pre-rotation events, once with the new signer
for post-rotation events. A future `verify_mixed_chain()` helper is planned.

### Step 6 — Revoke or archive the old key

```bash
# Vault: set the minimum decryption version to prevent use of the old version
vault write transit/keys/aevum-signer/config min_encryption_version=<new_version>

# Do NOT delete the old key — it is needed to verify historical chain entries.
# Keep it in Vault with sign permission removed but verify permission retained.
```

---

## Emergency Key Rotation

Use this procedure when the signing key is suspected or confirmed compromised.

**Time to execute:** ~15 minutes if Vault is available.

### Step 1 — Identify the compromise boundary

Determine the last event that is **trusted** (i.e., signed before the compromise
window). Record its `event_id`, `sequence`, and `prior_hash`.

```python
# Identify last trusted event (by timestamp or operator knowledge)
events = engine._ledger.all_events()
last_trusted = events[known_good_index]
print(f"Last trusted: seq={last_trusted.sequence}, id={last_trusted.event_id}")
```

### Step 2 — Rotate the key immediately

```bash
# Vault: immediately rotate
vault write -f transit/keys/aevum-signer/rotate

# If the old key version must be disabled for signing NOW:
vault write transit/keys/aevum-signer/config \
  min_encryption_version=<new_version>
```

This ensures no new signatures can be produced with the compromised key.

### Step 3 — Emit a security incident event

```python
engine.commit(
    event_type="security.incident",
    payload={
        "incident_type": "key_compromise_suspected",
        "affected_key_id": compromised_key_id,
        "last_trusted_sequence": last_trusted.sequence,
        "last_trusted_event_id": last_trusted.event_id,
        "responder": "security@example.com",
    },
    actor="security-incident-response",
)
```

### Step 4 — Resume from the last trusted event

```python
new_signer = VaultTransitSigner(
    vault_url="https://vault.example.com",
    key_name="aevum-signer",
    key_version=new_version,
)
new_chain = Sigchain(
    signer=new_signer,
    initial_sequence=last_trusted.sequence,
    initial_prior_hash=AuditEvent.hash_event_for_chain(last_trusted),
)
```

### Step 5 — Re-emit any events in the compromise window

If events after `last_trusted` are untrusted (could have been tampered), they must
be re-ingested from external sources and re-signed with the new key. Each re-emitted
event should include `causation_id=original_event_id` and a note in the payload.

### Step 6 — Anchor to Rekor

After rotation, submit the new chain tail to Rekor for external anchoring:

```bash
AEVUM_REKOR_URL=https://your-rekor-instance \
    aevum publish --checkpoint
```

The Rekor entry provides a third-party timestamp proving the post-rotation events
existed before a given wall-clock time.

### Step 7 — Notify stakeholders

File an incident report and notify any downstream systems that verify Aevum
chain integrity. Share the Rekor checkpoint URL as evidence of chain continuity.

---

## VaultTransitSigner — Status (Phase C-3)

**Status: Documented, not yet implemented as Python code.**

The `VaultTransitSigner` pattern is specified in:
- [`docs/spec/aevum-signing-v1.md`](../spec/aevum-signing-v1.md) — wire format and
  prehashed signing API contract.
- [`docs/adrs/adr-004-signer-interface.md`](../adrs/adr-004-signer-interface.md) —
  pluggable Signer architecture decision.

The expected Vault Transit API call is:

```http
POST /v1/transit/sign/{key_name}
Content-Type: application/json

{
  "input": "<base64(sha3_256_digest)>",
  "prehashed": true,
  "signature_algorithm": "pkcs1v15"
}
```

The `prehashed: true` flag is required because Aevum passes a 32-byte SHA3-256
digest to `Signer.sign()`, not the raw message.

**Not yet tested against live Vault.** The procedure above is correct by
construction from the Vault Transit API documentation (v1.17) and the Aevum
signing spec, but has not been exercised against a running Vault server in this
development environment.

**Reference implementation:** A `VaultTransitSigner` class is planned for
`aevum-sdk` (a separate package). When available, its package version and the
Vault version it was tested against will be recorded here.

**Last tested against Vault:** N/A — not yet implemented as Python code.

---

## InProcessSigner Rotation

If you are using `InProcessSigner` (the default, for development / non-regulated
deployments), key rotation means restarting the process. Each restart generates a
new Ed25519 key. The sigchain then picks up from the last persisted event (via
`PostgresLedger._resume_chain_from_db()`) but with a new `signer_key_id`.

For `InProcessSigner`:
- **Rotation is automatic** on every process restart.
- **No planned rotation** is possible without a restart.
- **Emergency rotation**: restart the process immediately.
- **Verification limitation**: `verify_chain()` only verifies against the current
  in-memory key. Historical events signed with a prior in-process key cannot be
  re-verified without storing the old public key externally.

For this reason, production deployments requiring historical chain verification
MUST use an external signer (VaultTransitSigner or KMS).

---

## See Also

- [`docs/spec/aevum-signing-v1.md`](../spec/aevum-signing-v1.md) — full signing spec
- [`docs/deployment/rekor-self-hosted.md`](rekor-self-hosted.md) — private Rekor setup
- [`docs/adrs/adr-001-single-sigchain.md`](../adrs/adr-001-single-sigchain.md) —
  why a single append-only chain
- [`docs/adrs/adr-004-signer-interface.md`](../adrs/adr-004-signer-interface.md) —
  pluggable Signer architecture
- [`THREAT_MODEL.md`](../../THREAT_MODEL.md) — tamper-detection window, key
  compromise threat surface
