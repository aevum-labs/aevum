# ADR-011: QAR/FOQA Analytics Layer — ExceedanceDetector, GatekeeperFilter, FOQABridge

Date: 2026-05-25
Status: Accepted
Deciders: Aevum Labs
Session: 3B

---

## Context and Problem Statement

Sessions 1A–2 built the FDR-equivalent (forensic) layer: the sigchain,
COSE_Sign1 receipt encoding, SqliteReceiptStore with three-tier crash protection,
and escalation to crash_protected tier for regulatory events.

The "black box for AI agents" architecture requires a second pillar: an
operational analytics layer analogous to aviation's QAR/FOQA system. While
the FDR layer answers "what happened?" for forensic investigation, the FOQA
layer answers "are we within safety parameters across sessions?" for ongoing
operational monitoring.

The design requirement from FAA AC 120-82 (the aviation reference) is:
- Detect safety-relevant operational patterns (exceedances) without storing
  individual event content
- De-identify data before it leaves operator premises
- Preserve a structural gatekeeper role (one key-holder who can re-link)
- Emit aggregate metrics that satisfy post-market monitoring regulations

---

## Decision

Three components implement the QAR/FOQA layer:

### 1. ExceedanceDetector (`aevum.core.exceedance`)

A stateful, per-session detector that processes `AevumReceipt` objects in
order and emits `ExceedanceEvent` objects when safety-relevant conditions
are met. Analogous to a GDRAS (Ground Data Replay and Analysis System).

- **Catalogue:** 15 exceedance types (EX-01 through EX-15), each with an
  aviation analogy, severity, and detection method.
- **Stateless exceedances (10):** EX-02, EX-03, EX-04, EX-05, EX-06, EX-09,
  EX-11, EX-12, EX-13, EX-15. Detected from single receipt fields.
- **Stateful exceedances (3):** EX-01 (rolling 60s retry count), EX-07 and
  EX-08 (rolling sigma outliers via `process_metric()`).
- **Deferred (2):** EX-10 and EX-14 require cross-session/cross-agent context.
  Documented in catalogue with `"deferred": True` flag. Not silently omitted.
- **Threading:** NOT thread-safe. One detector per session.
- **SigChain wiring:** Optional `exceedance_detector` parameter added to
  `Sigchain.__init__()`. Non-blocking: detection failures are logged and do not
  block `new_event()`.

### 2. GatekeeperFilter (`aevum.otel.gatekeeper`)

De-identification filter modeled on the FAA AC 120-82 gatekeeper role.

- **Pseudonymization:** HMAC-SHA256(identifier, key)[:16], prefixed "anon-".
  Deterministic, irreversible without the key.
- **Key requirement:** Fails loudly (`RuntimeError`) without a 32-byte key.
  No dev-mode bypass — a filter without a key provides no protection.
- **Key source:** Constructor parameter or `AEVUM_GATEKEEPER_KEY_HEX` env var.
- **Fields stripped:** prompt_text, response_text, user_id, user_email,
  user_name, ip_address, raw_input, raw_output, and any field whose key name
  contains "user", "email", "name", "ip", "phone", or "address".

### 3. FOQABridge (`aevum.otel.foqa_bridge`)

Receives `ExceedanceEvent` objects, filters through `GatekeeperFilter`, and
emits de-identified OTel aggregate metrics.

- **Metrics emitted:**
  - `aevum.exceedance.count` (counter): dimensions exceedance_id, exceedance_name, severity
  - `aevum.session.count` (counter): total sessions observed
- **No individual session data exported:** session_id and agent_id are
  intentionally absent from metric attributes, even pseudonymized.
  Rationale: a pseudonymized session_id in a high-cardinality metric enables
  correlation attacks via external session timing data.
- **One instance per deployment** (not per session).
- **OTel provider:** Accepts optional `meter_provider` parameter (like
  `AevumOTelBridge` accepts `tracer_provider`). Falls back to global OTel
  MeterProvider.

---

## Alternatives Considered

### Alternative A: Store individual exceedances in SqliteReceiptStore

Each ExceedanceEvent would be stored in a new table in the receipt database,
alongside the existing `receipts` and `ambient_receipts` tables.

**Rejected because:**
- Violates the "aggregate only" export principle — individual exceedance events
  with session identifiers would be in the same store as receipts.
- Adds schema migration complexity to the receipt store.
- FOQABridge's aggregate-only design is the key privacy guarantee. Individual
  storage would weaken it.

### Alternative B: Extend AevumOTelBridge to emit exceedance metrics

Add exceedance detection logic to the existing bridge, keeping everything
in the aevum-otel package.

**Rejected because:**
- ExceedanceDetector is stateful (rolling windows) and per-session. AevumOTelBridge
  is stateless and per-event. Merging them would violate the single-responsibility
  principle.
- ExceedanceDetector is in aevum-core, which has no OTel dependency. Keeping
  detection in core and emission in aevum-otel maintains the correct dependency
  direction.

### Alternative C: Differential privacy on aggregate metrics (deferred)

Add a noise mechanism (Laplace or Gaussian) to the aggregate counts to provide
formal differential privacy guarantees before export.

**Deferred because:**
- Privacy budget design (ε, δ parameters) requires consultation with a privacy
  engineer and an understanding of the expected query patterns.
- The current aggregate-only design (no individual session attributes) already
  provides strong practical protection without formal DP.
- Planned for v0.8.0.

---

## Consequences

### Positive

- **EU AI Act Art. 72** post-market monitoring satisfied: aggregate exceedance
  metrics provide the operational safety data required without exposing
  individual session content.
- **GDPR Art. 5(1)(e)** storage limitation less restrictive for de-identified
  aggregate data (pseudonymized data is still personal data; aggregate counts
  without re-linking capability are not).
- **FAA AC 120-82** institutional design preserved: the gatekeeper role
  (structural separation, key held outside management) is faithfully implemented.
- **FDR + QAR dual layer** provides both forensic and operational analytics,
  mirroring the aviation "black box" model.
- **15 exceedance types** cover the major safety-relevant AI agent behaviors,
  with clear aviation analogies that aid communication with safety regulators.

### Negative / Risks

- **EX-10 and EX-14 not implemented:** Two exceedance types require v0.8.0
  multi-agent tracking. Safety monitoring gaps exist for concurrent tool
  conflicts and A2A communication failures.
- **EX-07, EX-08 require 10+ samples:** Low-traffic sessions may not trigger
  sigma-based outlier detection reliably.
- **EX-06 requires date in version string:** Operators using opaque version
  identifiers will not trigger stale policy detection.
- **ExceedanceDetector not thread-safe:** Multi-threaded deployments require
  external synchronization.

### Invariants Added

None. Existing invariants (barrier evaluations in receipts, COSE encoding) are
the inputs; ExceedanceDetector is a consumer, not a producer of canonical truth.

---

## Related ADRs

- ADR-009 (Black box receipt format — AevumReceipt is the input to ExceedanceDetector)
- ADR-010 (Three-tier receipt storage — SqliteReceiptStore stores receipts; ExceedanceDetector processes them separately)

## References

- FAA AC 120-82 (April 2004): FOQA gatekeeper role, data protection, aggregate reporting
- EU AI Act Art. 72: Post-market monitoring for high-risk AI systems
- GDPR Art. 5(1)(e): Storage limitation; Recital 26: definition of anonymization
- UNECE WP.29 UN R157 DSSAD: "why it happened" data (implemented in escalation.py)
- docs/standards/foqa-deidentification-spec.md: Full de-identification specification
- docs/architecture/foqa.md: Component diagram and limitation table
