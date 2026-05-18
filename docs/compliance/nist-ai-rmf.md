# NIST AI RMF 1.0 alignment

**Status:** Guidance document  
**Reference:** NIST AI Risk Management Framework 1.0 (January 2023)

---

## Overview

The NIST AI Risk Management Framework (AI RMF 1.0) provides a voluntary framework
for organizations to identify and manage AI-associated risks throughout the system
lifecycle. Aevum maps naturally to the RMF's four core functions — GOVERN, MAP,
MEASURE, and MANAGE — because Aevum is built around the same foundational concerns:
governance accountability through policy enforcement, risk identification through consent
and provenance tracking, measurement through cryptographic integrity, and risk management
through unconditional barriers and human-in-the-loop controls.

---

## GOVERN

The GOVERN function addresses organizational practices, policies, culture, and
accountability structures that enable AI risk management.

Aevum's policy architecture implements GOVERN through Cedar, a formally specified
attribute-based authorization language. The policy engine
(`aevum.core.policy.cedar_engine.CedarPolicyEngine`) evaluates every governed operation
(ingest, query, review, commit, replay) against Cedar policies before execution. No
operation bypasses policy evaluation.

**Cedar policies in `packages/aevum-core/src/aevum/core/policies/`:**

| Policy file | Purpose |
|---|---|
| `barriers.cedar` | Five absolute `forbid` rules that cannot be overridden by any principal or configuration |
| `permits.cedar` | Base `permit` rules for routine operations; overridable by forbid rules |
| `autonomy.cedar` | Five autonomy levels (L1–L5) governing how much independent action is permitted without human approval |
| `gdpr_pii.cedar` | Unconditionally blocks any graph write where `context.contains_raw_pii == true` |
| `trifecta.cedar` | Prevents simultaneous untrusted-source reads, private-data reads, and external exfiltration |

**Autonomy levels** (`autonomy.cedar`): L1 requires human approval for all consequential
actions; L2 for irreversible actions; L3 for irreversible actions; L4–L5 progressively
relax restrictions. Operators configure the level for their deployment. High-risk AI
deployments should use L1 or L2.

**Complication lifecycle:** Complications (third-party integrations) follow a governed
lifecycle: registered → approved → active → suspended. Each transition is recorded in
the episodic ledger. No complication can become active without an explicit operator
approval. This gives operators ongoing accountability for what extensions are running.

For GOVERN, Aevum provides the enforcement substrate — Cedar policies and the
complication lifecycle. Organizational governance decisions, policy content, and
accountability structures are deployer responsibilities.

---

## MAP

The MAP function addresses understanding of AI risks in context: who is affected, what
data is used, and what purposes are served.

Aevum's consent ledger (`aevum.core.consent.ledger.ConsentLedger`) implements MAP. Every
`query` and `replay` operation requires an active `ConsentGrant` before any graph
traversal occurs. Barrier 3 in `barriers.py` enforces consent as a precondition —
there is no opt-out.

**`ConsentGrant` fields** (`aevum.core.consent.models.ConsentGrant`):

| Field | Type | Purpose |
|---|---|---|
| `grant_id` | str | Unique grant identifier |
| `subject_id` | str | The entity whose data is covered |
| `grantee_id` | str | The actor authorized to operate on this data |
| `operations` | list[str] | Subset of {ingest, query, replay, export} |
| `purpose` | str | Specific, auditable statement of purpose |
| `classification_max` | int (0–3) | Maximum data sensitivity this grant covers |
| `granted_at` | str | ISO 8601 grant timestamp |
| `expires_at` | str | ISO 8601 expiry — grants must be renewed |
| `authorization_ref` | str \| None | Reference to external authorization document |
| `revocation_status` | active \| revoked \| expired | Current grant state |

**Purpose binding:** The `purpose_specific` field validator rejects vague purposes
("any", "all", ""). Every consent grant represents a documented, specific risk scope.
This aligns with MAP's goal of identifying the conditions in which risks materialize.

**Subject-level scoping:** Each grant is scoped to a `subject_id`. Cross-subject queries
require separate grants per subject. This prevents purpose creep at the data layer.

**OR-Set CRDT semantics:** The consent ledger uses OR-Set conflict-free replicated data
type semantics. Revocation is immediate and wins in Aevum's single-node case. Grants
carry a `revocation_status` field that auditors can query to reconstruct the authorization
state at any past point in time.

---

## MEASURE

The MEASURE function addresses how AI risks are tracked, evaluated, and assessed.

Aevum's sigchain (`aevum.core.audit.sigchain.Sigchain`) implements MEASURE. Every
`commit` operation appends a cryptographically signed, chained event to the episodic
ledger.

**Cryptographic properties of each chain entry** (`sigchain.py`):

| Property | Implementation |
|---|---|
| Per-entry Ed25519 signature | Signed over SHA3-256(canonical JSON) of the signing fields |
| SHA3-256 payload hash | Independent hash over the event payload |
| Prior hash chaining | `prior_hash` references the hash of the previous entry; chain begins at `GENESIS_HASH = sha3_256(b"aevum:genesis")` |
| UUID7 event IDs | Time-ordered identifiers enabling temporal ordering of audit records |
| Optional ML-DSA 65 dual-signing | Post-quantum resistant second signature |
| Optional RFC 3161 TSA token | Third-party trusted timestamp proving the event existed at a specific time |

**`verify_chain(events)`** (`Sigchain.verify_chain`):

Validates the entire chain from genesis:
1. Checks `prior_hash` linkage for every entry.
2. Verifies the SHA3-256 payload hash matches payload content.
3. Verifies the Ed25519 signature against canonical signing fields.
4. If dual-sig is present, verifies the ML-DSA 65 signature.

Returns `True` only if all entries are intact. Any modification to a historical entry
breaks the chain from that point forward.

**`replay()`** reconstructs any past decision from the episodic ledger: the inputs at
the time, the policy state, the consent grants in effect, and the output produced. This
enables post-hoc measurement of decision quality and policy compliance — the core
requirement of MEASURE.

---

## MANAGE

The MANAGE function addresses how risks are prioritized, responded to, and monitored.

Aevum implements MANAGE through unconditional barriers and the `review` function.

**Unconditional barriers** (`aevum.core.barriers`): Five hardcoded barriers that execute
before any governed operation. These cannot be disabled, overridden, or reconfigured at
runtime.

| Barrier | What it unconditionally prevents |
|---|---|
| 1 — Crisis Detection | Proceeding with any graph operation when crisis keywords are detected in ingested content |
| 2 — Classification Ceiling | Returning data above the requesting actor's clearance level |
| 3 — Consent | Any graph traversal without an active consent grant |
| 4 — Audit Immutability | Any deletion or modification of episodic ledger entries (`ImmutableLedgerError`) |
| 5 — Provenance | Ingesting data without a valid provenance record (`source_id` required) |

**The `review` function:** Halts a decision workflow and presents structured context to
a human reviewer. The reviewer's decision — approve or reject — is itself recorded as a
sigchain entry, creating an auditable human-in-the-loop gate.

**Break-glass:** Operators may configure a break-glass procedure for emergency access
elevation. Break-glass activations are recorded in the sigchain and cannot be silently
undone.

---

## Gaps and deployer responsibilities

Aevum is a context kernel, not a complete AI risk management system. The following are
outside Aevum's scope:

- **Model evaluation:** Aevum does not evaluate AI model outputs for bias, fairness, or
  accuracy. Deployers must implement model evaluation separately.
- **Clinical safety:** The crisis detection barrier is keyword-based. It is explicitly
  not clinically validated (see `barriers.py` docstring). It is not a medical device.
  False negatives and false positives are possible. It must not be the sole safety
  control for applications serving users in mental-health or crisis contexts.
- **Incident response runbooks:** Aevum records that incidents occurred; it does not
  manage response. Deployers need operational runbooks.
- **Organizational AI governance policies:** Aevum provides Cedar-based enforcement
  substrate. Deployers must write and maintain the policies reflecting their governance
  decisions.
- **Model inventory and documentation:** AI RMF GOVERN 1.7 requires documentation of AI
  models in use. Aevum does not maintain a model registry.
- **Cross-system data lineage:** Aevum tracks provenance through its governed membrane.
  Lineage from upstream ETL pipelines is the deployer's responsibility.

---

## References

- NIST AI RMF 1.0: <https://doi.org/10.6028/NIST.AI.100-1>
- `packages/aevum-core/src/aevum/core/barriers.py` — Unconditional barriers
- `packages/aevum-core/src/aevum/core/audit/sigchain.py` — `verify_chain()`
- `packages/aevum-core/src/aevum/core/consent/models.py` — `ConsentGrant`
- `packages/aevum-core/src/aevum/core/policies/` — Cedar policy files
