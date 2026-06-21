# Aevum Invariants — Proof Sketches and Failure Mode Analysis

*The "NTSB Flight Recorder Handbook" for the Aevum black box receipt format.*

Seven formal invariants are defined in
`packages/aevum-core/src/aevum/core/invariants.py`.
This document explains each invariant, why it matters, how it is enforced,
what failure looks like, and how it is tested.

---

## I1-APPEND_ONLY

**Formal statement:** No sigchain entry may be modified or deleted after commit.

**Why it matters:** A mutable log is not a log. The entire forensic value of
the episodic ledger depends on its immutability. If an adversary can modify
past entries, they can rewrite history — precisely what aviation FDRs are
designed to prevent.

**How enforced:**
- `AuditEvent` is a `@dataclasses.dataclass(frozen=True)` — Python raises
  `FrozenInstanceError` on any attempted field assignment after creation.
- Receipt bytes are attached via `dataclasses.replace(event, receipt_cbor=...)`,
  which creates a new frozen instance rather than mutating the original.
- SQLite receipt store: WAL journal mode, no UPDATE/DELETE on the receipts
  table. This is enforced by application convention (`SqliteReceiptStore`
  never issues UPDATE/DELETE against the table) — there is no database-level
  trigger rejecting modification.
- Rekor v2 entries are immutable by design — the transparency log is append-only.

**Failure mode:** An adversary with direct database write access could alter
records. The Ed25519 signature would then fail verification — detectable by
any party running `aevum verify-receipt`. However, between the modification
and the next verification, the tampered state is undetected. This is the same
threat model as FDR crash-protected enclosures: they prevent post-crash
modification of the physical medium, but not modification of a copied dataset.
The mitigation is Rekor v2 external witnessing (I6-CRASH_PROTECTED).

**Test reference:**
`packages/aevum-publish/tests/test_receipt_encoder.py::TestSigchainReceiptWiring::test_existing_tests_unaffected`
`packages/aevum-core/tests/audit/test_sigchain.py` (verify frozen dataclass)

**Aviation analogy:** FDR crash-protected enclosure (bright orange, CSMU)
prevents post-crash modification of the physical recording medium. The enclosure
survives 3400g/6.5ms shock and 1100°C for 60 minutes. The forensic value of the
FDR depends entirely on this physical immutability guarantee.

---

## I2-COMPLETENESS

**Formal statement:** Every agent action produces exactly one receipt before
acknowledgment.

**Why it matters:** A log with gaps is not a log. If any agent action can
complete without producing a receipt, the forensic record is incomplete —
and an adversary who knows this can time their actions to exploit the gap.

**How enforced:**
- `ReceiptEncoder` is wired into `SigChain.new_event()`. If `receipt_encoder`
  is configured, a receipt is created and attached before `new_event()` returns.
- The receipt is attached via `dataclasses.replace(event, receipt_cbor=receipt_cbor)`.
  The event returned to the caller always carries the receipt.
- If `receipt_encoder.encode()` raises, the exception is caught and logged
  at WARNING level (non-blocking). The exception does not propagate.
- `NullBackend.submit()` never raises (dev mode guarantee).

**Failure mode:** If `receipt_encoder.encode()` raises silently (current
non-blocking behavior), the event is returned without a receipt. This degrades
I2 from "enforced" to "best effort." The warning log is the indicator.
In production deployments: monitor for the warning log line
`"Receipt encoding failed (non-blocking)"` and treat it as a P1 alert.

**Test reference:**
`packages/aevum-publish/tests/test_receipt_encoder.py::TestSigchainReceiptWiring::test_sigchain_with_encoder_attaches_receipt`
`packages/aevum-publish/tests/test_receipt_encoder.py::TestSigchainReceiptWiring::test_sigchain_without_encoder_no_receipt`

**Aviation analogy:** FDR must record continuously; a gap in the recording
timeline is itself a reportable event. ICAO Annex 6 requires that FDR
recording faults be detectable and reported to the crew.

---

## I3-INTEGRITY

**Formal statement:** Every receipt carries an Ed25519 signature over SHA3-256
of the canonical payload.

**Why it matters:** An unsigned receipt is hearsay. The Ed25519 signature
transforms the receipt into cryptographically authenticated evidence: any party
with the issuer public key can verify that the receipt was produced by the
Aevum kernel at the claimed time and has not been modified since.

**How enforced:**
- `ReceiptEncoder.encode()` computes:
  1. `protected_bstr = cbor2.dumps(protected_header)` (includes SCITT fields)
  2. `payload_bstr = receipt.to_cbor_payload()`
  3. `sig_structure = cbor2.dumps(["Signature1", protected_bstr, b"", payload_bstr])`
  4. `digest = SHA3-256(sig_structure)`
  5. `signature = Ed25519.sign(digest)` via `Signer.sign(digest)`
- The signature covers the protected header (including iss, sub, iat) and the
  payload. Any modification to either invalidates the signature.
- SHA3-256 is used (FIPS 202) rather than SHA-256 (FIPS 180-4) for prehash.

**Failure mode:** If the signing key is compromised, an adversary can produce
valid-looking receipts. Historical receipts produced before the compromise
remain valid — Ed25519 verification against the old public key still passes.
The mitigation is key rotation (new kid field, new issuer URI) and transparency
log witnessing (historical entries in Rekor cannot be modified).

**Post-quantum signing:** ML-DSA-65 dual-signing is implemented (`DualSigner`).
When active, receipts carry both Ed25519 and ML-DSA-65 signatures, providing
post-quantum resilience. Classical-only (Ed25519-only) posture remains
available and is explicitly noted on the resulting sigchain entries.

**Test reference:**
`packages/aevum-publish/tests/test_receipt_encoder.py::TestReceiptEncoder::test_encode_signature_verifiable`

**Aviation analogy:** FDR data is authenticated by the NTSB using the aircraft's
recorded parameter calibration data. Without the calibration record, the raw
FDR data is uninterpretable. The Ed25519 public key serves the same role as
the calibration data: it is the reference against which authenticity is measured.

---

## I4-BOUNDARY_ENFORCEMENT

**Formal statement:** Cedar policy is evaluated for every tool invocation
before execution.

**Why it matters:** Governance without enforcement is theater. If a policy
can be bypassed — whether by an adversarial prompt, a misconfigured agent, or
a software bug — the entire governance framework fails at its most critical
moment.

**How enforced:**
- Cedar `forbid` policies are evaluated via `PolicyEngine.is_permitted()` before
  every tool invocation in the governed membrane.
- Five unconditional barriers (defined in `aevum.core.barriers`) are hardcoded
  and non-bypassable:
  1. **Crisis** — halts on crisis-signal content before any graph write
  2. **Classification Ceiling** — blocks any action on data above the deployment ceiling
  3. **Consent** — blocks context traversal without a valid, scoped consent grant
  4. **Audit Immutability** — blocks deletion or mutation of audit records
  5. **Provenance** — blocks irreversible + consequential action without a human checkpoint
- ADR-005 mandates fail-closed behavior: if Cedar policy evaluation fails or
  raises an exception, the decision is DENY, not ALLOW.

**Failure mode:** If Cedar policy evaluation fails open (returns allow on
exception), the boundary is not enforced. ADR-005 explicitly prohibits this.
The five unconditional barriers are hardcoded Python code (in `barriers.py`) that
runs before the policy engine and cannot be bypassed by any policy configuration.
They are additionally mirrored as Cedar `forbid` policies in `barriers.cedar`
(defense-in-depth) — but the hardcoded layer is what makes the guarantee
unconditional, since it fires even when Cedar is not installed.

**Test reference:**
`packages/aevum-core/tests/barriers/` (barrier unit tests)
`packages/aevum-conformance/` (conformance suite, invariant I4 tests)

**Aviation analogy:** GPWS (Ground Proximity Warning System) cannot be disabled
by the crew during normal operations. The EGPWS "pull up" alert is a hardcoded
barrier equivalent — it fires regardless of crew input and cannot be suppressed
by any cockpit configuration.

---

## I5-MONOTONIC_SEQUENCE

**Formal statement:** The sequence counter is strictly monotonically increasing.

**Why it matters:** Gaps in sequence numbers indicate missing events. If
sequence numbers can be reused or skipped, an auditor cannot distinguish
between "no events happened" and "events happened but were deleted."

**How enforced:**
- `SigChain._sequence` is incremented at the start of `new_event()`:
  `self._sequence += 1` before any other operation.
- The sequence number is included in the signing fields and therefore covered
  by the Ed25519 signature. A forged or reordered sequence number would
  invalidate the signature.
- `verify_chain()` checks that each event's `prior_hash` matches the previous
  event's chain hash — any gap in the sequence would break the chain.

**Failure mode (thread safety):** `SigChain` is NOT thread-safe by design.
If two concurrent calls to `new_event()` race on `self._sequence`, sequence
numbers could be duplicated. Callers must serialize access to `SigChain` or
use one `SigChain` instance per thread. This is a documented requirement, not
a bug — imposing thread safety would require locks that conflict with async
event loops.

**Test reference:**
`packages/aevum-publish/tests/test_receipt_encoder.py::TestSigchainReceiptWiring::test_existing_tests_unaffected`
`packages/aevum-core/tests/audit/test_sigchain.py` (sequence monotonicity tests)

**Aviation analogy:** FDR frame counter provides a continuous sequence number
for every recorded data frame. Missing frames — gaps in the counter — are
immediately identifiable and trigger investigation.

---

## I6-CRASH_PROTECTED

**Formal statement:** In production mode, receipt blob is written to WORM or
replicated off-host before acknowledgment.

**Why it matters:** A log stored only on the agent's host can be destroyed with
the host. Physical destruction, ransomware, or a cloud provider incident can
eliminate the entire audit record. External replication makes the audit record
survive any single-host failure.

**How enforced (by mode):**

| Mode | Backend | Protection level |
|------|---------|-----------------|
| Dev | `NullBackend` | None — dev only, not crash-protected |
| Production | `RekorV2Backend` | External replication to Rekor before acknowledgment |
| Production (future) | `ScittTsBackend` | SCITT Transparency Service inclusion |

`RekorV2Backend.submit()` raises `RuntimeError` if `AEVUM_REKOR_URL` is not
configured (S-13 enforcement). It does not fall back silently to a local store.

**Note on WORM storage:** Full WORM storage (e.g., S3 Object Lock) is a
deployment configuration, not enforced by the library. The library provides
the data; the operator provides the storage tier. See the deployment guide for
S3 Object Lock configuration.

**Failure mode:** `RekorV2Backend` submission failure is non-blocking
(logged at WARNING, execution continues). This is intentional for availability:
a Rekor outage must not block the agent. The consequence is that I6 degrades
to "best effort" during Rekor outages. Monitor the warning log line
`"Receipt encoding failed (non-blocking)"`.

**Note on AmbientContextReceipt and polling:** `SigChain.capture_ambient_context()`
is a method callers invoke explicitly. The library does NOT poll at 1 Hz
internally — background threads would impose concurrency requirements the
library cannot make safely. Callers that want 1 Hz FOQA-style sampling must
implement their own timer loop outside the library.

**Test reference:**
`packages/aevum-publish/tests/test_receipt_encoder.py::TestTransparencyBackends`
`packages/aevum-publish/tests/test_receipt_encoder.py::TestSigchainReceiptWiring`

**Aviation analogy:** FDR physical crash protection: bright orange (not black)
crash-survivable memory unit rated for 3400g/6.5ms shock, 1100°C for 60 minutes,
and 6000m depth water pressure. The physical enclosure ensures the data survives
the accident being investigated.

GADSS (Global Aeronautical Distress and Safety System) adds a second layer:
continuous 1-minute position reporting to a third-party satellite network that
the operator cannot disable. Rekor v2 serves the same role as GADSS: an
operator-independent external record that survives the loss of the aircraft.

---

## I7-SCITT_REGISTERED

**Formal statement:** In production mode, a transparency service inclusion
proof is available within the Maximum Merge Delay.

**Why it matters:** Third-party verification requires a transparency log with
cryptographic inclusion proofs. Rekor v2 provides external witnessing but is
not a SCITT Transparency Service in the formal sense (it uses RFC 6962-style
Merkle trees rather than the SCITT receipt format). Full I7 satisfaction
requires a proper SCITT TS that issues SCITT receipts with inclusion proofs.

**Current status:** I7 is aspirational for v0.7.0.

- `ScittTsBackend` exists as a stub that raises `NotImplementedError`.
- Full SCITT TS registration requires ScrAPI (draft-ietf-scitt-scrapi) to
  stabilize as an RFC.
- `RekorV2Backend` provides partial coverage: it witnesses receipts in an
  external append-only log with inclusion proofs, but the log format is
  RFC 6962 (Certificate Transparency-style), not the SCITT receipt format.

**Production path:** When ScrAPI becomes an RFC and a conformant SCITT TS
is available, activate `ScittTsBackend` with the TS URL. The `ScittTsBackend`
implementation (Session 2+ scope) will:
1. POST the COSE_Sign1 receipt to the TS via ScrAPI
2. Receive a SCITT receipt (inclusion proof)
3. Return the inclusion proof bytes as the submission reference

**Recommended Maximum Merge Delay:** ≤24 hours for production deployments.

**Test reference:** I7 is not testable in dev mode. The conformance suite
tests that `ScittTsBackend.submit()` raises `NotImplementedError` — this is
the expected behavior documented as the conformance test for I7 in v0.7.0.

**Aviation analogy:** GADSS ADT (Automatic Dependent Surveillance) provides
continuous 1-minute position reporting to a third-party satellite network
(INMARSAT or Iridium) that the operator cannot disable. The satellite network
is the SCITT Transparency Service equivalent: an independent party that
receives and stores the record, providing an inclusion proof (the satellite
acknowledgment) that the record existed at a specific time.
