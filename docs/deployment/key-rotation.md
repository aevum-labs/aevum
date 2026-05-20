# Key Rotation — Aevum Signing Keys

This document covers planned and emergency rotation of Aevum signing keys,
sigchain continuity guarantees during rotation, and the operational status of
the `VaultTransitSigner` integration.

---

## Background

Every Aevum episodic ledger entry is signed with an Ed25519 key held by a
`Signer` implementation. The key identity is recorded on each event as
`signer_key_id`. A chain verification failure occurs if the verifier's
current key does not match the key that produced a given signature.

Key rotation therefore requires:
1. Completing all in-flight chain entries with the **old key** before
   switching to the **new key**.
2. Storing a **key transition event** that cryptographically bridges the two
   keys (signed by the old key, containing the new `signer_key_id`).
3. Updating the verifier to accept entries signed by either key during the
   transition window.

---

## Planned Rotation Procedure

Use this procedure when rotating on a scheduled cadence or at policy-driven
intervals.

### Prerequisites

- Write access to the signing key store (Vault Transit, AWS KMS, or the
  in-process key file for non-regulated deployments).
- The Aevum service is healthy and the chain is in a consistent state.
- `verify_sigchain()` passes against the current chain before you begin.

### Steps

1. **Verify the current chain**

   ```bash
   aevum-cli chain verify --output json
   ```

   Confirm `"integrity": "ok"` before proceeding. Abort if verification fails.

2. **Generate the new key**

   _Vault Transit example:_
   ```bash
   vault write -f transit/keys/aevum-signing-key-v2 type=ed25519
   ```

   Note the new key name and initial version number.

3. **Record a `key.rotation.planned` event with the old key**

   This event must be the **last event signed by the old key** and must
   include the new key's identifier:

   ```python
   chain.new_event(
       event_type="key.rotation.planned",
       payload={
           "old_key_id": old_signer.key_id,
           "new_key_id": new_signer.key_id,
           "reason": "scheduled rotation",
           "effective_at": datetime.now(UTC).isoformat(),
       },
       actor="ops/key-rotation-script",
   )
   ```

4. **Swap the signer in the running service**

   Replace the `Signer` instance on the `Sigchain` with the new-key signer.
   For long-running processes this typically means a rolling restart with
   the new key credential pre-provisioned.

5. **Record a `key.rotation.complete` event with the new key**

   ```python
   chain.new_event(
       event_type="key.rotation.complete",
       payload={
           "old_key_id": old_signer.key_id,
           "new_key_id": new_signer.key_id,
       },
       actor="ops/key-rotation-script",
   )
   ```

6. **Verify the chain spans both keys**

   ```bash
   aevum-cli chain verify --output json
   ```

   The verifier must succeed across the rotation boundary. Chain entries
   before the rotation event carry `signer_key_id=old_key_id`; entries after
   carry `signer_key_id=new_key_id`. The verifier resolves the correct public
   key per-entry using `signer_key_id`.

7. **Retire the old key** (after retention period)

   Do not delete the old key until all replays covering pre-rotation events
   have been completed and archived. Minimum retention: 90 days or your
   compliance policy, whichever is longer.

### Sigchain Continuity Proof

The `prior_hash` chain is computed over event content (including
`signer_key_id`) but does NOT require a single consistent key across the
whole chain. The `key.rotation.planned` event, signed by the old key,
acts as the explicit bridge: it is discoverable in the ledger and records
both key identifiers. Any verifier can reconstruct the rotation sequence
from the ledger alone without out-of-band metadata.

---

## Emergency Rotation Procedure

Use this procedure when a key is compromised or suspected compromised.

> **Do not delay.** A compromised key can be used to forge chain entries
> that appear valid. Every minute of delay widens the tamper window.

### Steps

1. **Immediately revoke the compromised key**

   _Vault Transit example:_
   ```bash
   vault write transit/keys/aevum-signing-key/config min_decryption_version=2
   vault write transit/keys/aevum-signing-key/rotate
   ```

   This invalidates the old key version for new signing operations without
   deleting historical signing records (which you need for chain verification).

2. **Restart Aevum with the new key**

   Provision the new key credential and restart the service. The service
   will begin signing with the new key immediately on startup.

3. **Record a `key.rotation.emergency` event**

   As soon as the service is back up, record:

   ```python
   chain.new_event(
       event_type="key.rotation.emergency",
       payload={
           "old_key_id": old_key_id,
           "new_key_id": new_signer.key_id,
           "reason": "key compromise",
           "incident_id": "<your incident tracker ID>",
           "effective_at": datetime.now(UTC).isoformat(),
       },
       actor="ops/emergency-rotation",
   )
   ```

4. **Identify the tamper window**

   The tamper window is the interval from when the key was compromised
   (or earliest possible compromise) to when the key was revoked. Identify
   all chain entries in this window and treat them as potentially tampered.

5. **Verify entries outside the tamper window**

   ```bash
   aevum-cli chain verify --from-sequence 1 --to-sequence <last_safe_sequence>
   aevum-cli chain verify --from-sequence <first_post_rotation_sequence>
   ```

6. **Notify affected parties**

   Follow your incident response procedure. For regulated deployments
   (FDA §11.10(e), EU AI Act), the tamper window must be reported to the
   responsible party and recorded in the compliance log.

---

## VaultTransitSigner — Operational Status

| Item | Status |
|------|--------|
| Specification | Documented in `docs/spec/aevum-signing-v1.md` §VaultTransitSigner |
| Protocol reference | `POST /v1/transit/sign/{key_name}` with `prehashed=true` |
| Python implementation (`aevum.core.audit.signer.VaultTransitSigner`) | **Not yet implemented** |
| Last tested against Vault | **Untested** — implementation not present |
| Planned for | Phase B (scheduled after Phase C) |

### Specification

The signing protocol for VaultTransitSigner is fully specified:

```
POST /v1/transit/sign/{key_name}
Content-Type: application/json
X-Vault-Token: <token>

{
  "input": "<base64(sha3_256_digest)>",
  "prehashed": true,
  "marshaling_algorithm": "asn1"
}
```

The `prehashed=true` parameter is critical: Aevum passes a 32-byte SHA3-256
digest to `signer.sign()`, not the raw message. The Vault Transit API must
receive `prehashed=true` to avoid double-hashing.

The `key_id` property should return:
`{vault_url}/v1/transit/keys/{key_name}:{version}`

The `provenance` property must return `"vault-transit"`.

### Testing Against a Vault Dev Instance

Once implemented, test against a Vault dev server:

```bash
vault server -dev &
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=<dev-root-token>
vault secrets enable transit
vault write -f transit/keys/aevum-signing type=ed25519

# Run the integration tests
uv run pytest packages/aevum-core/tests/test_vault_signer.py -v
```

Update this table when the implementation ships:

| Vault version | Tested by | Date | Result |
|---------------|-----------|------|--------|
| _(pending)_   | _(pending)_| _(pending)_| _(pending)_ |

---

## Multi-Node Deployments

In multi-node deployments each node carries its own signing key. The
sigchain is per-node. Key rotation on one node does not affect other nodes.

Cross-node chain correlation uses `correlation_id` and `causation_id`, not
shared keys. Each node's `signer_key_id` is distinct and registered in the
provenance named graph (`urn:aevum:provenance`).

---

## Related Documents

- `docs/spec/aevum-signing-v1.md` — Full signing specification
- `docs/deployment/rekor-self-hosted.md` — Transparency log anchoring
- `THREAT_MODEL.md` §InProcessSigner Tamper-Detection Window — why an
  external signer is required for regulated deployments
