# ADR-007: External chain verification via Sigstore Rekor v2

Date: 2026-05-06
Status: Proposed
Deciders: Aevum Labs
Confidence: Medium

## Context and Problem Statement

Aevum's sigchain provides tamper-detection within a deployment: if an event is
modified after signing, `verify_sigchain()` returns False. But this detection
requires the verifier to trust that the chain has not been wholesale replaced by
an adversary who also holds the signing key and can regenerate all hashes.

For adversarial-resistant verification — where the auditor does not fully trust
the deployment operator — the chain must be externally witnessed. Certificate
Transparency solved an analogous problem for TLS certificates: by publishing
Signed Tree Heads to external logs, any party can verify that a certificate
existed before a given time and has not been silently revoked without record.

The Sigstore project's Rekor v2 (sigstore/rekor-tiles) is a GA, open-source,
CNCF-associated transparency log that uses the same Merkle tree / STH pattern,
supports arbitrary artifact types, and publishes Signed Tree Heads that can be
independently verified.

## Decision Drivers

- Adversarial-resistant audit: external witness makes silent chain replacement
  detectable even if the operator is compromised
- FDA 21 CFR §11.10(e): "independently record" — external witness is the
  strongest interpretation of "independent"
- Legal admissibility: an externally-witnessed timestamp provides stronger
  evidence than an operator-signed timestamp alone (analogous to RFC 3161
  qualified timestamping)
- Optionality: most deployers will not need external verification; those that
  do (regulated financial, FDA GxP, high-security government) should have a
  supported path

## Considered Options

1. **aevum-publish complication using Rekor v2, batched checkpoints (this decision)**
2. Real-time per-event Rekor submission
3. Private Trillian/Rekor instance only
4. No external verification (current behaviour)

**Option 1** — An optional complication that, on a configurable schedule (every N
events or every M seconds, whichever comes first), computes the chain's current
terminal state `(sequence, prior_hash, signer_key_id, system_time)`, signs it, and
submits it to a Rekor v2 endpoint as a `hashedrekord` entry. The Rekor inclusion
proof (log index + inclusion proof bytes) is recorded as a `transparency.checkpoint`
AuditEvent in the local sigchain. An external auditor can then: (a) fetch
`transparency.checkpoint` events from the local chain; (b) query the Rekor endpoint
for the inclusion proof; (c) independently verify the checkpoint was published at
the claimed time.

**Option 2** — Submit every AuditEvent to Rekor at write time. Provides maximum
external coverage but adds 50–500ms latency per event (Rekor round-trip) and makes
Rekor availability a dependency on the Aevum write path. Not acceptable for
high-throughput or availability-sensitive deployments.

**Option 3** — Require deployers to run a private Trillian/Rekor instance. Maximum
control, no dependency on external services, but adds significant operational
complexity for most deployers. Addressed by making the endpoint configurable —
private Rekor instances are supported without code changes.

**Option 4** — Current behaviour. Sufficient for internal audit use cases.
Not sufficient for adversarial-resistant verification or deployments where the
operator is also the auditee.

## Decision Outcome

Option 1, with a configurable Rekor endpoint (default: public Rekor v2 at
`rekor.sigstore.dev`; overrideable for private instances via
`AEVUM_PUBLISH_REKOR_URL`).

Checkpoint frequency is configurable: `AEVUM_PUBLISH_EVERY_N_EVENTS` (default 100)
and `AEVUM_PUBLISH_EVERY_SECONDS` (default 300). The complication fires on
whichever threshold is reached first.

The `transparency.checkpoint` AuditEvent payload includes:

```json
{
  "rekor_log_index": 42317,
  "rekor_entry_hash": "sha256:<hex>",
  "rekor_server": "https://rekor.sigstore.dev",
  "chain_sequence": 100,
  "chain_prior_hash": "<64-hex-SHA3-256>",
  "inclusion_proof": "<base64-encoded proof bytes>"
}
```

The Rekor submission uses the SHA-256 hash of the JSON-serialised checkpoint
record `{sequence, prior_hash, signer_key_id, system_time}` as the artifact
hash, signed with the deployment's Ed25519 key (via `Signer.sign()`).

### Authorised Part 2 code scope

- New package: `packages/aevum-publish/`
- Import path: `aevum.publish`
- Core class: `PublishComplication` implementing the complication manifest protocol
- HTTP client: `httpx` (already in the ecosystem); no official Python Rekor v2
  client — call the rekor-tiles tile-server HTTP API directly
- No changes to `aevum-core`; `transparency.checkpoint` goes in `AuditEvent.payload`
  (open `dict`), requiring no schema version bump

### Consequences

**Good:** External verification without operator trust; configurable endpoint
supports both public and private Rekor; inclusion proofs stored in the local chain
create a self-contained audit bundle; zero latency impact for non-publishing
deployments.

**Bad:** Public Rekor means checkpoint hashes are public — not a privacy issue
(hashes are not PII) but the existence of the chain becomes visible; for maximum
confidentiality, run a private Rekor instance. No official Python Rekor v2 client —
must implement HTTP calls directly; maintenance risk if the API changes.

**Residual risk:** (a) **Rekor availability**: public Rekor v2 has "best effort"
SLA; the complication must buffer checkpoints and retry on failure — never block
the Aevum write path. (b) **Rekor v1 → v2 transition**: Rekor v1 is in maintenance
mode; build against v2 (rekor-tiles) only and document that v1 is not supported.
(c) **Log shard rotation**: Rekor v2 shards by year; `rekor_server` in the
checkpoint payload captures the shard URL for future verification.

## Technical notes

Rekor v2 entry submission:
```
POST /api/v1/log/entries
Content-Type: application/json
{
  "kind": "hashedrekord",
  "apiVersion": "0.0.1",
  "spec": {
    "signature": { "algorithm": "Ed25519", "content": "<base64_sig>" },
    "data": { "hash": { "algorithm": "sha256", "value": "<hex_digest>" } }
  }
}
```

The artifact is the SHA-256 hash of the JSON-serialised checkpoint record.
The signature is produced by `Signer.sign(digest)` using the deployment's key.

## Related ADRs

- ADR-001 (Single sigchain — the chain being externally witnessed)
- ADR-004 (Signer interface — the key used to sign checkpoint submissions)
- ADR-008 (Multi-agent correlation — cross-chain links verifiable via Rekor proofs)
