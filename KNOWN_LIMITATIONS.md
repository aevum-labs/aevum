# Known Limitations

This document lists genuine, current gaps in Aevum — things the product does
not yet do, areas with thin production validation, or open design questions.
It exists so a deployer or auditor can see the edges of the system rather than
discover them by surprise.

Unlike a roadmap, nothing here is a promise of future delivery. An item is
added when a real gap is found and removed only when the gap is closed;
closed items move to [`CHANGELOG.md`](CHANGELOG.md).

One category is forward-looking by design and is marked as such below:
compliance- and standards-adjacent items (FIPS 140-3 module certification,
RFC 4998/ERS, SCITT) that depend on a regulated customer's requirements or on
an external standards process, not on Aevum's own roadmap.

---

## Product gaps

### OTel bridge does not emit structured agent identity

`AuditEvent.actor` is a free-form string, not a structured `agent_id` /
`agent_name` pair, so `AevumOTelBridge` cannot emit the OTel GenAI semantic
convention spans `gen_ai.agent.name` / `gen_ai.agent.id`. The receipt store
carries a structured `agent_id`, but the OTel bridge only has access to
`AuditEvent`s, not `AevumReceipt`s, at span-emit time.

### No resource-ceiling barrier

The five unconditional barriers govern *what* can be accessed; none caps
*how much* a single agent session can consume — tokens, wall-clock time,
external calls, or cost. There is no canonical resource unit, and a
hardcoded ceiling would need per-deployment configuration, which is in
tension with the barriers being unconditional. A Cedar policy is the more
likely home for this than a sixth barrier. See THREAT_MODEL.md — "What Aevum
Does Not Protect Against" (resource exhaustion).

### Consent does not flow through to derived artifacts

Crypto-shredding destroys the subject's DEK, making the source plaintext
unrecoverable — but an embedding already computed from that plaintext is
itself plaintext sitting in an external vector store, and shredding the DEK
does not reach it. Aevum has no mechanism today for a consent revocation to
gate retrieval of artifacts derived from governed data. The intended shape is
not an Aevum-owned vector store, but a `consent_check(subject, purpose)` hook
that an adopter's retrieval path calls into; no reference implementation
exists yet.

### SQLite WAL sidecars are not secure-deleted on rotation

After `rotate_operational()`, and on the consent crypto-shred path, the WAL
is not checkpointed/truncated and rows are not secure-deleted — the `-wal`
and `-shm` sidecar files can retain plaintext after the corresponding row is
logically gone. This undercuts the deletion-honesty and GDPR crypto-shred
guarantee for data that passed through the WAL.
(`packages/aevum-core/src/aevum/core/audit/sqlite_store.py`)

### liboqs must be installed separately for ML-DSA-65

ML-DSA-65 dual-signing (`DualSigner`) requires the `liboqs` native library to
be pre-installed on the deployment host — it is not bundled with the
`liboqs-python` pip package. See
[`docs/deployment/liboqs.md`](docs/deployment/liboqs.md).

### AevumOTelBridge backends are not validated against live infrastructure

The Grafana Tempo and Langfuse setup instructions in
[`docs/learn/otel-bridge.md`](docs/learn/otel-bridge.md) are written from
each backend's documented OTLP ingestion contract, not confirmed against a
live Tempo or Langfuse instance.

### Crisis-barrier false-negative rate beyond the fixed probe set is unmeasured

The five unconditional barriers pass every adversarial probe in Aevum's fixed
test set, but that set targets known attack patterns. The false-negative
rate against novel adversarial inputs in production is not known. See
THREAT_MODEL.md's adversarial-prompt section.

### Production validation data for the oxigraph store is thin

`aevum-store-oxigraph` (small deployments) and `aevum-store-postgres`
(team/production deployments) are positioned by deployment size, but no
production deployment has run long enough at real multi-tenant workload to
confirm that split, rather than just postgres for everything, is the right
line to draw.

### Two near-identical "subject" concepts are not unified

`ConsentLedger`'s subject (the GDPR/CCPA data subject) and
`CommitmentKeyStore`'s principal (the bound credential identity of an actor —
an OIDC `sub`, a SPIFFE ID, or a DID) are conceptually distinct but
structurally near-identical erasure mechanisms (SQLite-backed,
`PRAGMA secure_delete=ON`, crypto-shred on destroy). They use deliberately
disjoint vocabulary (`scope` / `principal` / `commitment_key_id`, never
"subject") so the two are not casually conflated in code or documentation,
but no shared abstraction or single mental model unifies them, and none is
currently planned.

### CommitmentKeyStore erasure is deployment-scoped, not per-principal

Destroying a `commitment_key_id` erases the ability to confirm or re-derive
**every** `principal_commitment` computed under that key — there is no way to
selectively erase one principal's commitment while leaving others under the
same key confirmable. For a deployment with many principals sharing one
commitment key, this is a much blunter instrument than
`ConsentLedger.shred()`'s per-subject granularity. Closing this gap needs no
signed-format change — `principal_commitment_key_id` already identifies which
key produced a commitment — it is purely an operational decision about how
`CommitmentKeyStore` mints keys.

---

## Compliance- and standards-adjacent (forward-looking)

These items depend on a regulated customer's requirements or on an external
standards process completing — not on Aevum's own feature roadmap. Unlike the
product gaps above, staying forward-looking here is intentional.

### FIPS 140-3 module certification

ML-DSA-65 implements the FIPS 204 algorithm standard; FIPS 140-3 *module*
certification — a security certification for the cryptographic module,
distinct from algorithm standardization — has not been obtained for either
the Ed25519 or ML-DSA-65 signing path. Whether a given build of the
`cryptography` package uses a FIPS 140-3-validated module also depends on the
host OS and OpenSSL configuration, not on Aevum. Use an HSM- or KMS-backed
signer for FIPS-required deployments; see THREAT_MODEL.md's HIPAA section.
Out of scope until a regulated customer requires it.

### RFC 4998 / ERS evidence-record interoperability

Aevum's durability position is that the write-time RFC 3161 timestamp is
best-effort/advisory, and re-anchoring — re-timestamping the Merkle root
before the prior TSA certificate expires — is the mechanism for surviving a
multi-year retention window. See
[`docs/durability/timestamp-longevity.md`](docs/durability/timestamp-longevity.md).
RFC 4998 Evidence Record Syntax interoperability is not implemented and
remains intentionally parked; it would only be taken up if a design partner
required ERS-format export.

### SCITT

`ScittTsBackend` is a stub. SCITT support targets the IETF SCRAPI draft
(`draft-ietf-scitt-scrapi`), which is not yet a finished specification. See
[`docs/standards/scitt-profile.md`](docs/standards/scitt-profile.md).

---

## See also

- [`CHANGELOG.md`](CHANGELOG.md) — resolved items move here.
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — trust assumptions and what Aevum
  does not protect against.
- [`NON-GOALS.md`](NON-GOALS.md) — what Aevum will never become. A non-goal
  is permanent by design; a limitation on this page is just not yet closed.
