# Aevum Threat Model

This document describes Aevum's trust assumptions, system boundaries,
what it protects against, and its known limitations. Read this before
deploying Aevum in a regulated or high-stakes environment.

Read this document alongside CONTROL_MAPPING.md.

---

## Version

Applies to: aevum-core v0.3.0+
Last reviewed: May 2026

---

## What Aevum is and is not

Aevum is a Python library that provides:

- A cryptographic audit trail (Ed25519-signed, SHA3-256 hash-chained)
- A consent-checked data access layer
- An append-only episodic ledger
- Human-in-the-loop review gates
- Five unconditional barriers (crisis, classification, consent,
  immutability, provenance)

Aevum is **not**:

- A network security tool (no mTLS, no SPIFFE/SVID identity)
- An authentication system (no identity issuance or token validation)
- A post-quantum cryptography implementation (Ed25519 is not
  quantum-resistant)
- A formal access-control enforcement boundary at the OS level (it is
  a library inside your process)
- A medical device or safety-critical system
- A system that prevents a determined insider with direct database access

---

## System Boundaries

### Inside Aevum's trust boundary

- The five governed functions (`ingest`, `query`, `review`, `commit`,
  `replay`) and their implementations in `aevum.core.engine`
- The five unconditional barriers
- The episodic ledger and sigchain (`urn:aevum:provenance`)
- The consent ledger (`urn:aevum:consent`)
- The knowledge graph (`urn:aevum:knowledge`)

### Outside Aevum's trust boundary

- The application process that imports and calls Aevum
- The Ed25519 private key (held in your process's memory by default)
- The storage backend (SQLite, Oxigraph, or PostgreSQL)
- The operating system and file system
- Network transport to the storage backend
- Any MCP host, HTTP client, or other caller of `aevum-server` or
  `aevum-mcp`
- The LLM or AI model making decisions

---

## Trust Assumptions

Aevum's guarantees depend on the following assumptions. If any
assumption is violated, the guarantee it supports degrades or fails.

### Assumption 1: The signing key is not compromised

**Guarantee supported:** Sigchain entries are authentic and have not
been fabricated after the fact.

**If violated:** An attacker with the private key can sign fabricated
AuditEvents that will verify as legitimate. The hash chain will appear
intact. There is no mechanism to detect this retroactively unless the
key compromise is identified through other means.

**Mitigation:** Use a KMS or HSM to hold the signing key outside the
application process. Implement key rotation on a defined schedule.
Monitor signing-key access.

---

### Assumption 2: The storage backend is not directly modified

**Guarantee supported:** Any modification to a stored AuditEvent breaks
the hash chain and is detectable on verification.

**If violated:** A database administrator with direct backend access can
delete or modify AuditEvents. The chain will break at the point of
modification and is detectable by `engine.verify_sigchain()` — but only
if verification is performed after the modification. Modification
followed by chain reconstruction using a compromised signing key would
not be detectable.

**Important distinction:** Aevum's ledger is tamper-**evident**, not
tamper-**proof**. It detects modification; it does not prevent it at
the storage layer.

**Mitigation:** Restrict database-level write access to the ledger
tables. Use PostgreSQL row-level security. For regulated deployments
where you need to prove the chain was intact at a specific moment,
consider external anchoring (RFC 3161 timestamps, OpenTimestamps).

---

### Assumption 3: The process running Aevum is not compromised

**Guarantee supported:** The five unconditional barriers cannot be
bypassed by configuration or complication code.

**If violated:** An attacker with code execution inside the Aevum
process can call the storage layer directly, bypassing the kernel. The
barriers are enforced in the kernel's code path — they are not OS-level
sandboxing.

**Mitigation:** Treat process-level compromise as a separate threat.
Apply standard application hardening: minimal privileges, container
isolation, seccomp profiles.

---

### Assumption 4: In-memory mode is not used in production

**Guarantee supported:** Sigchain integrity persists across restarts.

**If violated:** All data, the sigchain, and the consent ledger are
lost on process restart. No tamper-evidence survives.

**Mitigation:** In-memory mode is appropriate only for development and
testing. Use `aevum-store-oxigraph` or `aevum-store-postgres` for any
persistent workload.

---

## What Aevum Protects Against

| Threat | Coverage | Notes |
|---|---|---|
| Unauthorized data access (consent bypass) | Unconditional — Barrier 3 | Checked before every graph operation |
| Data ingestion without provenance | Unconditional — Barrier 5 | source_id required on every ingest |
| Above-clearance data access | Unconditional — Barrier 2 | Classification ceiling enforced at query |
| Crisis content propagation | Unconditional — Barrier 1 | See crisis detection limitations below |
| Ledger modification without detection | Detectable via verify_sigchain() | Tamper-evident, not tamper-proof |
| Complication code bypassing barriers | Architectural | Complications cannot access storage directly |
| Irreversible actions without approval | Via review() + veto-as-default | Requires application to call create_review() |
| Consent revocation delays | Immediate at next operation | Single-node only — see distributed limitation below |

---

## What Aevum Does Not Protect Against

| Threat | Status | Recommended mitigation |
|---|---|---|
| Network-level attacks (MitM, replay at transport layer) | Out of scope | TLS at reverse proxy; mTLS for internal services |
| Identity spoofing (fake actor claims) | Out of scope | JWT validation + actor mapping in your application |
| LLM prompt injection | Not directly | Input validation; purpose-built guardrail tooling |
| Training data poisoning | Out of scope | Separate data governance pipeline |
| Insider threat with direct DB admin access | Detected, not prevented | External anchoring; restricted DB access; RLS |
| Model bias or discriminatory outputs | Out of scope | Bias testing; NIST AI RMF MAP function |
| Quantum adversary forging signatures | Not protected | Ed25519 is not post-quantum; PQ migration planned |
| Cross-tenant isolation at OS level | Out of scope | Separate Engine instances per tenant; OS-level isolation |
| Data loss in in-memory mode | By design | Use persistent storage backend in production |

---

## Classification Ceiling Limitation

Barrier 2 enforces the classification ceiling at **query time**, not at
ingest time (`apply_classification_ceiling()` in `barriers.py`).

**What it does:** When an actor queries the knowledge graph, Barrier 2
checks whether any requested subject's recorded classification level
exceeds the actor's declared clearance. If any subject exceeds the
ceiling, the entire query is blocked: the operation returns
`error_code="classification_blocked"` and a `barrier.triggered` audit
event is appended. No partial or redacted result is returned.

**What it does not do:**

- It does not prevent above-clearance data from being **ingested**.
  `ingest()` accepts data at any classification level regardless of the
  calling actor's clearance. The barrier fires only on read, not on write.
- It does not prevent an actor with direct database access from reading
  above-clearance data outside Aevum's query path.
- It does not enforce multi-level security (MLS) at the OS or filesystem
  level. Classification is a runtime label checked by the kernel — not an
  OS-enforced access boundary.
- It does not apply to data returned through the `replay()` function.
  `replay()` returns a verbatim AuditEvent from the provenance graph;
  classification ceiling is not re-applied to replayed payloads.

**Practical implication:** If you ingest sensitive data with a high
classification label and a low-clearance actor later calls `query()`,
Barrier 2 will block that query entirely — the actor receives no results
at all. However, the data is present in the storage backend and visible
to anyone with direct backend access (see Assumption 2). For workloads
requiring strict ingest-time classification control, apply access controls
at the ingest boundary (e.g., policy in your application layer or in an
OPA sidecar) before calling `ingest()`.

---

## Crisis Detection Limitations

Barrier 1 (Crisis) flags content matching crisis patterns before any
graph operation.

**What it does:** Checks ingested and queried content against defined
crisis indicators. Matching content stops the operation and returns a
crisis envelope.

**What it does not do:**

- It is not validated to any clinical standard
- It is not a medical device under FDA or EU MDR classification
- It does not replace human clinical judgment
- False negatives (missed crisis content) are possible
- False positives (incorrectly flagged content) are possible
- False-negative and false-positive rates are not currently published
  against a public benchmark

**If your application serves users in mental-health, crisis, or
vulnerable-population contexts:** do not rely on Barrier 1 alone.
Complement it with human review, clinical safety measures, and
domain-validated tooling. Barrier 1 is a first-line content screen,
not a clinical safety system.

---

## Consent Revocation Semantic

Aevum's consent ledger uses an OR-Set CRDT (Conflict-free Replicated
Data Type) for grant management.

**Single-node deployments:** Revocation is reliable and immediate.
`engine.revoke_consent_grant(grant_id)` makes data unreachable at the
next operation.

**Distributed deployments (multiple Engine instances):** The OR-Set's
"add wins on concurrent add/remove" merge semantic means that if a
grant-add and a grant-revoke for the same grant occur simultaneously
on two nodes, the add will win on merge. This is not the expected
behavior for permission revocation in regulated contexts, where revoke
should win.

**Mitigation for distributed deployments:** Coordinate consent
operations through a single authoritative node, or implement
application-level sequencing that ensures revocations are fully
propagated before new operations are permitted. A revoke-wins merge
strategy is on the roadmap.

---

## Replay Scope

`engine.replay(audit_id=...)` retrieves and cryptographically verifies
the signed record of a past operation from `urn:aevum:provenance`.

**What it does:** Returns the exact AuditEvent recorded at the time of
the original operation, with chain verification proving the record has
not been modified since it was written.

**What it does not do:**

- Does not re-execute the agent's reasoning
- Does not re-call the LLM
- Does not reconstruct the full knowledge graph state at the time of
  the original operation (the graph may have changed since)
- Does not guarantee byte-identical reproduction of LLM outputs

For auditing and forensics, replay provides a verified record of what
was ingested, queried, or committed. It does not provide a simulation
of what the agent would have done if run again today.

---

## Kernel-Event Impersonation via REMEMBER (D-08)

An application could attempt to forge a kernel or governance event (e.g. a fake
`complication.approved` or `session.committed`) by passing a kernel-reserved
`event_type` to `commit()` (the public REMEMBER path). Because `commit()` produces
cryptographically valid, correctly-chained ledger entries, such a forged event would
be indistinguishable from a genuine kernel assertion when reading the sigchain by
`event_type` alone.

**Mitigation:** `commit()` rejects any `event_type` whose prefix matches a
kernel-reserved namespace: `ingest.`, `query.`, `review.`, `commit.`, `replay.`,
`barrier.`, `policy.`, `agent.`, `session.`, `complication.`, `capture.`,
`context.`. The rejection returns `error_code="reserved_event_type"` and records a
`commit.rejected` event in the sigchain. Application events must use unreserved
namespaces (e.g. `app.`, `action.outcome.`, or any custom prefix not in the reserved
list). This boundary is enforced in the kernel code path and is covered by a
drift-guard canary test (`test_canary_all_kernel_namespaces_reserved`) that will fail
if a future kernel namespace is added without also reserving it.

**Residual risk:** An actor with direct storage access can bypass the public API
entirely, writing raw ledger rows without passing through `commit()`. This is
mitigated by storage access controls (PostgreSQL RLS, restricted DBA access) and
by `verify_sigchain()`, which detects chain inconsistencies. Forged events written
through the public path still carry the caller's `actor` field, providing forensic
attribution.

**Design flag:** A namespace registry (an explicit allowlist of kernel-owned prefixes
maintained alongside `_RESERVED_PREFIXES`) would prevent future drift without
requiring manual synchronisation of the canary. Tracked as a future hardening item.

---

## Deployment Recommendations for Regulated Workloads

### HIPAA (healthcare, PHI)

- Use `aevum-store-postgres` with encrypted tablespace
- Hold the signing key in a KMS or HSM; do not leave it in process memory
- Restrict PostgreSQL write access to the ledger tables via row-level
  security
- Implement separate BAAs for any MCP/tool calls that process PHI
- Complement Aevum's audit controls with FIPS 140-3 validated encryption
  at rest; Aevum's default in-process Ed25519 configuration is not
  FIPS 140-3 validated

### EU AI Act high-risk systems

- Aevum addresses Article 12 (record-keeping) and parts of Article 19
- Separately implement Articles 9 (risk management), 10 (data governance),
  11 (technical documentation), 14 (human oversight), 15 (robustness)
- Retain logs for at least 6 months (Article 26(6)); 10 years for
  technical documentation (Article 18)
- See CONTROL_MAPPING.md for the full Article-by-Article mapping

### SOC 2 Type II

- Aevum's sigchain supports CC7.2 (monitoring) and CC7.3 (incident
  detection)
- Complement with network monitoring and access logging at the
  infrastructure layer

### Production minimum (all deployments)

- Use a persistent storage backend (not in-memory)
- Hold the signing key outside the application process where possible
- Run `engine.verify_sigchain()` on a scheduled basis, not only on-demand
- Alert on sigchain verification failures
- Restrict direct database write access to the ledger tables

---

## InProcessSigner Tamper-Detection Window (D-01)

The default `InProcessSigner` holds the Ed25519 private key in the agent
process's heap memory.

**What it does:** Signs each AuditEvent as it is appended to the ledger,
producing a hash-chained, signed sequence that is tamper-evident via
`engine.verify_sigchain()`.

**What it does not do:**

- It does not prevent an attacker who has achieved code execution inside
  the process from reading the private key directly from memory and forging
  backdated entries.
- It does not detect tampering that occurs *and is concealed* before
  `verify_sigchain()` is next called.

**Exact tamper-detection window:** The window between two successive calls
to `engine.verify_sigchain()`. Any modification that is applied and repaired
(including chain reconstruction with a stolen key) within this window will
not be detected. The window is operator-controlled — you set the schedule
for `verify_sigchain()` calls.

**Exact mitigation:**

- Move the signing key out of process memory. Use `VaultTransitSigner`
  (HashiCorp Vault Transit) or `PKCS11Signer` (HSM/hardware key). With an
  external signer, the private key is never resident in the agent process,
  so process compromise cannot yield the key.
- Anchor the chain root to an external transparency log (via `aevum-publish`)
  at a frequency shorter than your acceptable tamper window. A Rekor checkpoint
  creates an external, publicly-verifiable record that the chain root existed
  at a specific time. An attacker who modifies history must also forge the
  external record, which is computationally infeasible.
- Recommended Rekor checkpoint frequency: every 100 events or 5 minutes,
  whichever comes first (`every_n_events=100, every_seconds=300` — the
  `aevum-publish` default). For regulated deployments with strict audit
  requirements, reduce to every 10 events or 60 seconds.

**Summary:** `InProcessSigner` is tamper-**evident**, not tamper-**proof**.
For regulated workloads, use an external signer and external anchoring.

---

## Crisis Barrier Evasion Techniques (D-02)

Barrier 1 (Crisis) uses keyword pattern matching against a fixed vocabulary.
This design is intentional — deterministic, auditable, zero false-negatives for
exact matches — but leaves documented evasion surfaces.

**Chunking:** An attacker can split crisis phrases across multiple `ingest()`
calls. `"i want to"` followed by `"kill myself"` in a second call will trigger
on the second call, but not on the first. The first call is not re-evaluated
when the second arrives.

*Mitigation:* Applications serving users where crisis detection is safety-critical
should maintain session context and evaluate concatenated content across recent
calls, not individual calls in isolation.

**Elliptical phrasing:** The crisis keyword set covers explicit, literal phrases
("want to die", "harm myself"). Elliptical or clinically coded language ("I
don't think I'll be around much longer", "I've made my arrangements") is not
covered. False-negative rates against natural-language crisis expression are not
benchmarked.

*Mitigation:* Do not rely on Barrier 1 as the sole safety gate for
mental-health, crisis, or vulnerable-population applications. Complement with
clinical-grade tooling that uses semantic understanding rather than keyword
matching. See "Crisis Detection Limitations" (above).

**Cultural and linguistic variation:** The current crisis vocabulary is
English-only and reflects US-centric crisis expression. Other languages, dialects,
and cultural idioms for distress are not covered.

*Mitigation:* For non-English deployments or multilingual user populations,
implement application-layer crisis screening with a multilingual model before
calling `ingest()`.

**What is not a mitigation:** Expanding the keyword set. Adding more keywords
increases false-positive rates without closing the evasion surface for
paraphrase. Pattern matching is a first-line screen; it is not a semantic
safety system.

---

## record_capture_gap() Ordering Limitation (D-03)

`engine.record_capture_gap()` writes a `capture.gap` AuditEvent to the sigchain
declaring that an out-of-band call (LLM, tool, MCP) was made outside the
complication framework.

**Ordering limitation:** The gap event is written *after* the out-of-band call
completes, not before. This means the sigchain records the gap retroactively
rather than as a predictive declaration.

**Practical consequence:** If the process crashes, is killed, or is interrupted
between the out-of-band call and the `record_capture_gap()` invocation, no gap
event is written. An auditor reviewing the sigchain would see no record of the
call. This is a forensic gap, not a security boundary violation — the barriers
are not affected.

**What the auditor sees in the retroactive case:** A gap event with a timestamp
after the call, with the interval between the prior sigchain event and the gap
event representing the unobserved window. The timestamp is the signing time of
the gap event, not the actual call time.

**What the auditor cannot determine:** The exact content of the LLM request or
response, the model called, or the latency of the call — unless `extra=` is
populated by the caller.

*Mitigation:* Write the gap event *before* making the out-of-band call where
possible (declare intent, then execute). Pass `model_hint`, `reason`, and
`extra` to provide maximum forensic context. For higher-assurance forensics,
use the appropriate complication (e.g., `AevumAnthropicAdapter`) rather than
`record_capture_gap()`.

See also: `docs/reference/five-functions.md` — record_capture_gap ordering note.

---

## OR-Set Consent Race Conditions (D-04)

*(Extends "Consent Revocation Semantic" above.)*

The consent ledger uses an OR-Set CRDT. The full race condition taxonomy:

**Case 1 — Concurrent add/revoke on separate nodes.** If a grant-add and a
grant-revoke for the same `grant_id` are applied simultaneously on two separate
Engine instances, the add wins on merge. This is the correct behavior for
eventually-consistent systems designed around availability, but is incorrect for
access-control systems where revoke must win.

**Case 2 — Revoke followed by re-add within the replication window.** If a
grant is revoked on node A, and a new grant with the same `grant_id` is created
on node B before the revoke has propagated, the new grant survives on merge.
From the auditor's perspective, it appears the grant was never revoked.

**Case 3 — Clock skew.** If two nodes have system clocks more than a few
seconds apart, the ordering of concurrent add/revoke pairs may differ between
nodes, leading to inconsistent merge outcomes.

**Consequence of Case 1 and Case 2:** An actor whose access was intended to be
revoked may retain access on nodes that have not yet received the revoke.

**Mitigation for distributed deployments:**

- Designate a single authoritative consent node. Route all consent mutations
  (add and revoke) through this node. Read replicas serve grant checks but never
  accept mutations.
- Use monotonically increasing `grant_id` values so that re-adds always have a
  higher ID than prior revokes, making the intent unambiguous in the merge
  history.
- Implement a quorum-read on consent checks in high-stakes paths: require a
  majority of nodes to confirm the grant before permitting the operation.
- A revoke-wins merge strategy is on the roadmap.

**Single-node deployments:** No race condition exists. Revocation is immediate
and permanent.

---

## Direct Storage Access Bypassing Barriers (D-05)

Aevum's unconditional barriers are enforced in the kernel code path (in
`aevum.core.engine`). They are not OS-level sandboxing or database-level
constraints.

**Attack surface:** Any actor with direct read/write access to the storage
backend (SQLite file, Oxigraph store, PostgreSQL database) can read, modify,
or delete data without passing through the kernel. The barriers will not fire
because the kernel is not involved.

**Specific bypass vectors:**

- A DBA with `psql` access can `DELETE` rows from the ledger table. This breaks
  the hash chain (detectable by `verify_sigchain()`), but only if verification
  is performed after the deletion.
- A process with file-system access to an Oxigraph store can open and modify
  the underlying files directly.
- An attacker who obtains the SQLite file (in-memory mode writes to a temp path;
  Oxigraph writes to disk) can manipulate it offline.
- A compromised signing key combined with direct storage access enables
  undetectable history rewriting (see Assumption 1, Assumption 2 above).

**What the sigchain provides against this threat:** Tamper *evidence*, not
tamper *prevention*. Any storage modification that is not followed by chain
reconstruction breaks `verify_sigchain()`. Modification followed by chain
reconstruction using the signing key is undetectable by the sigchain alone.

**Mitigations:**

- Restrict PostgreSQL write access to ledger tables using row-level security
  (RLS). Grant the Aevum application role INSERT-only on ledger tables; no
  UPDATE or DELETE.
- Anchor the chain to an external transparency log (`aevum-publish`). External
  anchoring creates a checkpoint that an attacker must also forge to conceal a
  storage modification.
- Enable PostgreSQL WAL archiving and point-in-time recovery. This provides an
  independent record of the storage state that cannot be modified retroactively.
- For Oxigraph deployments, store the data directory on a write-once filesystem
  or use filesystem-level integrity monitoring (e.g., AIDE, Tripwire).
- Run `engine.verify_sigchain()` on a scheduled basis (not only on-demand) and
  alert on failure.

---

## aevum-maintainer Self-Governance Attack Surface (D-06)

`aevum-maintainer` provides the self-governance layer: it allows Aevum's own
principles and policies to be reviewed, approved, and committed back to the
sigchain. This creates a recursive trust surface.

**Specific risks:**

**Principles tampering:** The signed principles file (`signed_principles.yaml`)
is verified at boot against the Ed25519 public key in `principles.yaml`. An
attacker who can modify both the principles file and the verification key (or
who compromises the signing key) can introduce malicious principles that appear
legitimate. The verification is only as strong as the key custody.

**Approval key concentration:** The break-glass escalation path in
`aevum-maintainer` allows a single authoritative reviewer to approve any action.
If that reviewer's credentials are compromised, an attacker can approve
arbitrary policy changes. There is no multi-party approval requirement.

**Self-referential policy bypass:** Because `aevum-maintainer` calls the same
`aevum-core` engine it governs, a sufficiently privileged attacker who can
modify the Cedar policies stored in the engine's knowledge graph can weaken the
policies that govern `aevum-maintainer` itself.

**OIDC token reuse:** `aevum-maintainer` uses OIDC tokens for ingest
authentication. If a token is intercepted (e.g., via a MitM on the OIDC
callback), it can be replayed within the token's validity window to authorize
unauthorized ingestion.

**Mitigations:**

- Store the principles verification key in an HSM or KMS, not on disk.
- Require multi-party approval for break-glass actions: two separate
  `aevum-maintainer` reviewer accounts must both approve before the action
  is committed.
- Treat the Cedar policy store as a security-critical artifact: back it up
  separately, monitor it for changes, and alert on unauthorized modifications.
- Use short-lived OIDC tokens (< 5 minute validity) and require token binding
  to mitigate replay.
- Audit all `aevum-maintainer` actions via `replay()` on a regular schedule.

---

## Gate G-11 through G-16 Adversarial Probe Results (D-07)

The following documents the results of adversarial probes run against
aevum-core v0.5.0 in the Phase G gate investigation (baseline:
`benchmarks/baseline-v0.6.0.json`, captured 2026-05-20).

| Gate | Probe | Result | Notes |
|------|-------|--------|-------|
| G-11 | Crisis barrier (Barrier 1) | PASS | Keyword `i want to kill myself` in ingested data triggers crisis envelope before graph write |
| G-12 | Consent barrier (Barrier 3) | PASS | No consent grant → ingest blocked immediately with `consent_required` |
| G-13 | Classification ceiling (Barrier 2) | PASS | Classification ceiling enforced at query via `check_classification_ceiling()`; ingest with classification=3 proceeds but query is blocked (`classification_blocked`) when ceiling=1 |
| G-14 | Audit seal (Barrier 4) | PASS | `InMemoryLedger.__delitem__` raises `BarrierViolationError`; sigchain remains intact after 50 commits |
| G-15 | Provenance veto (Barrier 5) | PASS | Empty `source_id` in provenance dict → `provenance_required` error before graph write |
| G-16 | Lethal trifecta prevention | PASS | Cedar `forbid` fires on `action='tool_call'` when all three taints present; two-taint composition permitted |

**G-13 finding — classification ceiling is query-time only:**
The ceiling is enforced when reading (via `check_classification_ceiling()` in
`query()`), not when writing. Data at any classification level can be ingested
regardless of the actor's clearance. When a query includes a subject whose
classification exceeds the ceiling, the entire query is blocked — not silently
filtered. This is documented in the "Classification Ceiling Limitation" section
above. For ingest-time classification control, apply policy in your application
layer or an OPA sidecar before calling `ingest()`.

**G-16 finding — trifecta action scope:**
The Cedar `forbid` rule for the lethal trifecta is scoped to
`action == 'tool_call'`. Integrators using the trifecta policy must use
`action='tool_call'` in their Cedar evaluation context. Using a different action
string (e.g., `'relate_graph_write'`) will not trigger the forbid. This is a
policy scoping clarification, not a defect; the probe initially used the wrong
action and was corrected.

**All six G-11 through G-16 probes pass.** No barriers were bypassed. No
regressions from v0.4.0 baselines.
