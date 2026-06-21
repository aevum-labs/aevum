# Aevum QAR/FOQA Analytics Layer Architecture

Date: 2026-05-25
Session: 3B
Status: Implemented (v0.7.0)

---

## The Dual-Layer Design (FDR + QAR)

Aevum's "black box for AI agents" is built in two complementary layers,
modeled on aviation's two-recorder system.

**FDR layer (Sessions 1A–2):** The forensic layer. Analogous to a Flight
Data Recorder — captures every event in a tamper-evident, append-only
sigchain. Optimized for "what happened" reconstruction via the `replay`
function. Components: `Sigchain`, `AevumReceipt`, `COSE_Sign1 encoder`,
`SqliteReceiptStore` (three-tier), escalation to crash_protected tier.

**QAR/FOQA layer (Session 3B):** The operational analytics layer. Analogous
to a Quick Access Recorder and the FAA's FOQA (Flight Operational Quality
Assurance) program. Processes receipt streams to detect safety-relevant
patterns (exceedances) and emits de-identified aggregate metrics. Components:
`ExceedanceDetector`, `GatekeeperFilter`, `FOQABridge`.

Together, these layers satisfy:
- Forensic investigation: FDR layer (full fidelity, cryptographic chain)
- Operational safety trending: QAR/FOQA layer (aggregate, de-identified)

---

## Component Diagram

```
Agent session
     │
     ▼
 SigChain.new_event()
     │
     ├── AuditEvent ──► AevumOTelBridge ──► OTel spans (tracing)
     │
     ├── AevumReceipt ──► COSE_Sign1 encoder ──► SqliteReceiptStore
     │                                               │
     │                                         escalate_if_triggered()
     │                                               │
     │                                         crash_protected tier
     │
     └── AevumReceipt ──► ExceedanceDetector ──► ExceedanceEvent list
                               (stateful,                │
                               per-session)              │
                                                         ▼
                                                  GatekeeperFilter
                                                  (pseudonymize,
                                                   strip PII)
                                                         │
                                                         ▼
                                                    FOQABridge
                                                    (OTel metrics)
                                                         │
                                                         ▼
                                            aevum.exceedance.count
                                            aevum.session.count
                                            (aggregate, de-identified)
```

---

## The 15 Exceedance Types

| ID | Name | Aviation Analogy | Severity | Detection Method |
|---|---|---|---|---|
| EX-01 | Tool Retry Loop | Unstable Approach | MEDIUM | Stateful: >3 retries in 60s rolling window |
| EX-02 | Forbidden Tool Invocation | Excessive Bank Angle | HIGH | Stateless: ClassificationCeiling barrier DENY |
| EX-03 | Safety Barrier Trip | GPWS Alert | CRITICAL | Stateless: any barrier_evaluations value DENY |
| EX-04 | Human Override Rejection | Hard Landing | HIGH | Stateless: human_override_action == REJECT |
| EX-05 | Agent Refusal | Go-Around | LOW | Stateless: action in (tool.refuse, agent.abstain, task.reject) |
| EX-06 | Stale Model or Policy Version | Configuration Warning | MEDIUM | Stateless: date in policy_version >30 days ago |
| EX-07 | Token Rate Outlier | Engine Exceedance | MEDIUM | Stateful: token_rate >3σ from rolling baseline (min 10 samples) |
| EX-08 | Latency Outlier | Airspeed Exceedance | MEDIUM | Stateful: latency_ms >3σ from rolling baseline (min 10 samples) |
| EX-09 | Context Window Overflow | Altitude Bust | HIGH | Stateless: prompt_tokens/context_window_size ≥0.95 |
| EX-10 | Concurrent Conflicting Tool Calls | TCAS Resolution Advisory | HIGH | **DEFERRED** (v0.8.0) — requires cross-session context |
| EX-11 | ODD Exit | ODD Exit | CRITICAL | Stateless: handoff_type == ODD_EXIT |
| EX-12 | Unacknowledged Transition Demand | Automation Handoff Refused | HIGH | Stateless: TRANSITION_DEMAND without handoff_to_agent_id |
| EX-13 | Minimum Risk Maneuver | Minimum Risk Maneuver | CRITICAL | Stateless: handoff_type == MINIMUM_RISK |
| EX-14 | Agent Communication Failure | Communications Failure | HIGH | **DEFERRED** (v0.8.0) — requires cross-agent message tracking |
| EX-15 | Primary Agent Failure | Crew Incapacitation | CRITICAL | Stateless: handoff_type == FAILURE |

---

## Known Limitations

### EX-10: Concurrent Conflicting Tool Calls (DEFERRED)

Detection requires knowing that multiple simultaneous tool calls from the
same agent made conflicting state mutations. This context is not available
in a single per-session receipt stream — it requires cross-session correlation
of tool call start/end times and the shared resource they targeted.

**Status:** Not implemented in `ExceedanceDetector`. The `EXCEEDANCE_CATALOGUE`
entry documents the deferral. Target: v0.8.0 when multi-agent A2A message
tracking is available.

### EX-14: Agent Communication Failure (DEFERRED)

Detection requires tracking inter-agent messages and detecting timeouts. The
A2A message correlation context is not available in a per-session receipt stream.

**Status:** Not implemented in `ExceedanceDetector`. Target: v0.8.0 multi-agent
tracking session (Session 9 in the receipt plan).

### EX-07, EX-08: Sigma-Based Outlier Detection

The sigma outlier check (`_is_sigma_outlier`) requires a minimum of 10 samples
in the rolling window before it will fire. In low-traffic sessions (fewer than
10 LLM calls in 60 seconds), these exceedances will not be detected reliably.

**Workaround:** For high-traffic deployments, this is not an issue. For
low-traffic deployments, consider lowering the minimum sample count or using
absolute thresholds instead of rolling sigma checks.

### EX-06: Stale Policy Version — Date-Embedded Version Strings Only

The stale policy check uses a regex to find an ISO 8601 date embedded in
`policy_version`. Deployers using opaque version strings (e.g., `"v3"`,
`"prod"`, commit hashes) will not trigger EX-06 even if the policy is stale.

**Recommendation:** Embed a date in your policy version strings:
`"policy-2026-05-25"` or `"v3-2026-05-25"`.

---

## Threading Model

**ExceedanceDetector:** NOT thread-safe. One detector per agent session.
The detector maintains mutable rolling window state (`deque` objects) that
is not protected by locks. Multi-threaded callers must either use one detector
per thread or protect with an external lock.

**FOQABridge:** Designed for shared use across sessions. OTel counter operations
(`add()`) are atomic in the OTel SDK. One `FOQABridge` instance per deployment
is the intended usage pattern.

**GatekeeperFilter:** Stateless after construction (key is read-only). Safe
for concurrent use.

---

## What Is NOT Implemented (Deferred Items)

| Item | Reason | Target |
|---|---|---|
| EX-10 cross-session detection | Requires multi-session context | Current gap |
| EX-14 cross-agent detection | Requires A2A message tracking | Current gap |
| Differential privacy on aggregate metrics | Privacy budget design required | Current gap |
| Federated exceedance detection across operators | Architecture decision pending | Current gap |
| Regulator-facing aggregate report (CSV/JSON) | Format TBD pending regulatory consultation | Current gap |
| gen_ai.agent.name / gen_ai.agent.id in OTel spans | AuditEvent lacks structured agent identity | Current gap (see KNOWN_LIMITATIONS.md) |
