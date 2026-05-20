# EU AI Act Article 12 — Clause-by-Clause Mapping

**Status:** Normative guidance for Aevum adopters  
**Reference:** Regulation (EU) 2024/1689, Article 12 (Logging requirements)  
**Applies to:** Aevum deployments backing high-risk AI systems under Annex III

---

## Overview

Article 12 requires high-risk AI systems to have logging capabilities enabling
automatic recording of events throughout the system's lifetime. This document
maps each Article 12 requirement to the specific Aevum primitive that satisfies
it — and is explicit about what Aevum does not provide, so adopters can
identify gaps in their deployment.

**Important:** Aevum is a third-party component, not a high-risk AI system.
The Article 12 obligation rests with the provider of the high-risk AI system
that uses Aevum. Aevum provides the technical infrastructure for logging; it
does not relieve providers of their documentation, registration, or oversight
obligations.

---

## Article 12(1) — Automatic Recording of Events

> High-risk AI systems shall be designed and developed with capabilities
> enabling automatic logging of events relevant to their operation throughout
> their lifetime.

**Aevum primitive:** The episodic ledger (`urn:aevum:provenance`).

Every call to `ingest()`, `query()`, `review()`, `commit()`, and `replay()`
appends a signed `AuditEvent` to the episodic ledger automatically. No
additional configuration is required. Events are recorded before the operation
completes — the ledger write is part of the operation's success path.

The ledger is append-only by design (Barrier 4 — Audit Seal). Events cannot
be deleted or modified after writing. `engine.verify_sigchain()` verifies
the integrity of the complete chain at any time.

**What Aevum provides:**

| Requirement | Mechanism |
|---|---|
| Automatic logging | All five functions write to the ledger unconditionally |
| Event timestamp | `valid_from` (ISO 8601) + `system_time` (HLC, nanoseconds) |
| Actor identification | `actor` field — required on every call, validated non-empty |
| Operation type | `event_type` field — e.g. `"ingest.accepted"`, `"query.completed"` |
| Payload integrity | `payload_hash` — SHA3-256 of the canonical JSON payload |
| Chain integrity | `prior_hash` — SHA3-256 of the previous event's signing fields |

**What operators must provide:**

- Mapping from their system's user or component identity to Aevum's `actor`
  field. Aevum does not validate identity claims — this is the caller's
  responsibility (see THREAT_MODEL.md — "Identity spoofing").
- Retention for the period required by sectoral law. Aevum does not enforce
  retention periods or automatic deletion policies.

---

## Article 12(2) — Specific Logging Requirements

Article 12(2) specifies what the log must capture. The EU AI Act text maps
to Aevum's AuditEvent fields as follows:

### Article 12(2)(a) — Period of each use

> The logging capabilities shall include at least: recording of the period
> of each use of the high-risk AI system.

**Aevum primitive:** `valid_from` + `valid_to` on every `AuditEvent`.

Every event carries an ISO 8601 `valid_from` timestamp set at write time
using the Hybrid Logical Clock (HLC). The HLC advances monotonically even
if the system clock is adjusted, preventing ordering anomalies. `valid_to`
is set for operations with a defined validity window (e.g., a consent grant).

Session start events (`event_type="session.start"`) and session end events
(`event_type="session.end"`) mark the period of each AI system session in
the ledger. `episode_id` groups related events into one AI decision episode.

### Article 12(2)(b) — Reference database

> Recording of the reference database used for verification.

**Aevum primitive:** `source_id` and `chain_of_custody` in the provenance
record attached to every `ingest()` call.

Every piece of data that enters Aevum must declare its provenance: the
`source_id` identifies the data source, and `chain_of_custody` lists the
systems it passed through before ingestion. This satisfies the requirement to
record which data sources backed each AI operation.

### Article 12(2)(c) — Input data

> Recording of the input data.

**Aevum primitive:** `payload_hash` — SHA3-256 of the canonical JSON payload.

Aevum does not store raw input data in the ledger payload; it stores the
hash. This is deliberate: raw personal data in an append-only ledger cannot
be erased (GDPR Article 17 tension — see `docs/compliance/gdpr-article-17.md`).

The hash satisfies Article 12(2)(c) for integrity verification: a verifier
can re-hash the original input data and confirm it matches the stored hash.
Operators must retain the original input data in a separate, erasable store
if they need to produce it to a notified body.

### Article 12(2)(d) — Person responsible for verification

> Recording of persons who performed the verification.

**Aevum primitive:** `actor` field on every `AuditEvent`, plus `ConsentGrant`
fields.

The `actor` field identifies who (or which system) performed each operation.
For `review()` operations, the `actor` is the human reviewer who approved or
vetoed the action. `ConsentGrant.grantee_id` identifies the agent authorized
to act on a subject's data.

Operators must map their identity system (OIDC, LDAP, service accounts) to
Aevum's `actor` field at their integration boundary. The kernel records what
it is told; it does not independently verify identity.

---

## Article 12(3) — Tamper Evidence

> The logging capabilities shall ensure a level of traceability in
> accordance with the intended purpose of the high-risk AI system.

**Aevum primitive:** Ed25519-signed, SHA3-256 hash-chained sigchain.

Every AuditEvent is signed with an Ed25519 private key. Each event carries
the SHA3-256 hash of the previous event's signing fields (`prior_hash`),
forming a Merkle-chain structure. Any modification to any event is detectable
via `engine.verify_sigchain()`.

### InProcessSigner limitation — honest assessment

!!! warning "InProcessSigner alone is NOT sufficient for Article 12 tamper-evidence in regulated deployments"

    `InProcessSigner` (the default) holds the Ed25519 private key in the same
    Python process as the AI system. It satisfies tamper-**detection**: any
    modification to the chain is detectable after the fact via signature
    verification.

    It does NOT satisfy tamper-**prevention**: an attacker who compromises
    the application process has access to the private key and can sign
    fabricated events that appear legitimate.

    For Article 12 compliance in Annex III deployments, Aevum's signing key
    must be held outside the AI system process. Two supported options:

    | Option | Implementation | Trust boundary |
    |---|---|---|
    | HashiCorp Vault Transit | `VaultTransitSigner` | Vault process (separate from AI system) |
    | AWS KMS / GCP KMS / Azure Key Vault | Custom `Signer` implementation | KMS service (outside application process) |
    | PKCS#11 HSM | Custom `Signer` implementation | Hardware boundary |

    See `packages/aevum-core/src/aevum/core/audit/signer.py` and
    THREAT_MODEL.md (Assumption 1 — signing key trust boundary) for details.

**External anchoring (AEVUM_REKOR_URL):** For deployments that need to prove
the chain was intact at a specific moment in time — not merely that it is
intact now — RFC 3161 trusted timestamps or Rekor transparency log anchoring
is required. Set `AEVUM_REKOR_URL` to publish chain checkpoints to Rekor
(sigstore). Without Rekor anchoring, an attacker who compromises both the
signing key and the storage backend could reconstruct a forged chain that
passes verification. With Rekor, the checkpoint entries serve as third-party
timestamped witnesses.

See THREAT_MODEL.md — Assumption 2 (storage backend) and ADR-007 (transparency
log) for the complete analysis.

---

## Summary: Aevum's Article 12 Coverage

| Article 12 requirement | Aevum coverage | Gap / operator action required |
|---|---|---|
| 12(1): Automatic event logging | **Full** — all five functions | None |
| 12(2)(a): Period of use | **Full** — valid_from / HLC | Retain logs for required period |
| 12(2)(b): Reference database | **Full** — source_id + chain_of_custody | Correctly set provenance on every ingest |
| 12(2)(c): Input data | **Partial** — payload_hash only | Retain original input data in separate store |
| 12(2)(d): Person responsible | **Partial** — actor field | Map identity system to actor at integration boundary |
| 12(3): Tamper evidence | **Partial** — detection without Vault/KMS signer | Use VaultTransitSigner or KMS signer in production; set AEVUM_REKOR_URL for external anchoring |

---

## Minimum Production Deployment for Article 12 Compliance

1. **External signer:** Configure `VaultTransitSigner` or a KMS-backed signer.
   Do not use `InProcessSigner` for regulated deployments.

2. **Persistent backend:** Use `aevum-store-postgres` or `aevum-store-oxigraph`.
   The default in-memory backend loses the chain on process restart.

3. **Actor mapping:** Validate tokens in your application layer and pass the
   verified identity as `actor` on every engine call.

4. **Retention policy:** Configure your storage backend to retain sigchain
   entries for the period required by your national AI Act implementation or
   applicable sectoral law. Aevum does not enforce retention.

5. **Transparency anchoring (recommended):** Set `AEVUM_REKOR_URL` to publish
   sigchain checkpoints to a Rekor transparency log. This provides third-party
   timestamped evidence that the chain was intact at each checkpoint.

---

## Generating an Audit Pack

The `aevum audit-pack` CLI command exports a signed JSON-LD document (PROV-O
vocabulary) containing all sigchain events for a session, suitable for
submission to a notified body:

```bash
aevum audit-pack SESSION_ID --output audit-session-123.jsonld
```

See [Audit Trails and Article 12](../concepts/audit-trails.md) for the full
audit pack schema and field descriptions.

---

## References

- Regulation (EU) 2024/1689 — EU AI Act
- Article 12: Logging requirements for high-risk AI systems
- Annex III: High-risk AI system use cases
- THREAT_MODEL.md — Assumption 1 (signing key), Assumption 2 (storage backend)
- ADR-007 — Transparency log (Rekor anchoring)
- `docs/compliance/gdpr-article-17.md` — GDPR Article 17 erasure pattern
- `docs/adrs/adr-004-signer-interface.md` — Signer interface design
