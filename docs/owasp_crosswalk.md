# OWASP Agentic Security Top 10 — Aevum Crosswalk

AEVUM — OWASP Agentic Security Initiative Top 10 Crosswalk
=================================================================
Reference: OWASP GenAI Security Project, Agentic AI Top 10 (published 2025-12-09)
Identifiers: ASI01 through ASI10
Last updated: v0.6.0 (2026-05-20)

✓ ASI01: Prompt Injection / Goal Hijacking
  Coverage: FULL
  Barriers: Barrier 1: Crisis, Barrier 5: Provenance
  • RELATE crisis barrier (Barrier 1) — blocks crisis/injection patterns before graph write
  • Cedar TaintLabel — tracks READS_UNTRUSTED across session context
  • GOVERN checkpoint — human review before consequential actions
  Note: Aevum's trifecta enforcement prevents the composition of READS_UNTRUSTED + READS_PRIVATE + CAN_EXFILTRATE, which is the mechanism by which prompt injection causes data exfiltration.

✓ ASI02: Insecure Tool / Plugin Use
  Coverage: FULL
  Barriers: Barrier 5: Provenance
  • Cedar TaintLabel entity — marks tools as CAN_EXFILTRATE
  • Trifecta Cedar forbid policy — blocks dangerous tool composition
  • GOVERN checkpoint — approves tool calls before execution
  Note: Tool calls are Cedar-evaluated before execution. The trifecta policy blocks tool compositions that combine untrusted input access with private data access and exfiltration.

✓ ASI03: Excessive Agency / Privilege Escalation
  Coverage: FULL
  Barriers: Barrier 5: Provenance
  • L1–L5 autonomy enforcement via Cedar context attributes
  • GOVERN checkpoint — non-bypassable for consequential actions
  • Cedar forbid policies — autonomy.cedar enforces L1/L2 constraints
  Note: L1-L5 autonomy levels are Cedar context attributes. At L1, every govern_approve requires human_checkpoint_completed. The autonomy level cannot be escalated by the agent itself.

✓ ASI04: Knowledge Base / Memory Poisoning
  Coverage: FULL
  Barriers: Barrier 1: Crisis, Barrier 3: Classification
  • RELATE crisis barrier — intercepts injected crisis content
  • pySHACL validation at RELATE time — validates fact structure
  • Provenance tracking — every fact has a signed source
  • Cedar ABAC at RELATE — checks classification and taint labels
  Note: Facts cannot enter the knowledge graph without passing crisis detection, SHACL validation, and Cedar ABAC. Provenance is mandatory and cryptographically signed.

~ ASI05: Cascading Agent Failure / Trust Chain Attacks
  Coverage: PARTIAL
  Barriers: Barrier 4: Audit Immutability
  • Sigchain with dual-sig — every session commit is signed
  • Session Merkle root — tampering detected across agent handoffs
  • GOVERN at each consequential step — no silent propagation
  • v0.6.0: AevumOTelBridge emits one OTel span per sigchain event; distributed
    tracing across agents surfaces cascading failure chains in any OTLP backend
    (Grafana Tempo, Langfuse, Jaeger). Privacy-safe by default: only audit_id
    is emitted unless OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true.
  Note: Aevum's sigchain detects tampering in replay. Full multi-agent trust chain validation requires A2A integration (Phase 6). OTel spans complement sigchain replay with real-time failure detection.

✓ ASI06: Human-in-the-Loop Bypass
  Coverage: FULL
  Barriers: Barrier 5: Provenance
  • GOVERN checkpoint — structurally non-bypassable
  • Automation bias warning — displayed at every substantive checkpoint
  • Cedar Barrier 5 — govern_approve forbidden without human_checkpoint_completed
  • Veto-as-default — timeout = veto, not approval
  Note: Cedar's Barrier 5 forbid cannot be bypassed by any permit. The human_checkpoint_completed flag is set ONLY by the GOVERN implementation after actual human input is received. Timeout always results in veto, never in approval.

✓ ASI07: Data Exfiltration / Leakage
  Coverage: FULL
  Barriers: Barrier 2: Consent, Barrier 3: Classification
  • Cedar TaintLabel — CAN_EXFILTRATE marks exfiltration-capable tools
  • Trifecta Cedar forbid — blocks untrusted+private+exfiltrate composition
  • Consent gate — navigate requires active consent for the purpose
  • Classification ceiling — Barrier 3 blocks above-ceiling data
  Note: The trifecta policy (trifecta.cedar) is Aevum's primary defense against the EchoLeak-class exfiltration pattern. All three taint labels must be simultaneously active for the attack to succeed — Cedar prevents this composition.

~ ASI08: Insecure Supply Chain / Dependency Confusion
  Coverage: PARTIAL
  • Ed25519-signed principles — verified at boot
  • Conformance suite — 9 invariants verified on every installation
  • pip-audit in CI — dependency vulnerability scanning
  • Trusted Publishing — signed PyPI wheels, no stored API keys
  • v0.6.0: key_scheme field in every AuditEvent wire format (Phase C-01) makes
    the signing algorithm explicit in every chain entry. Auditors can verify that
    the key scheme has not changed unexpectedly across the chain. Valid registry:
    {"ed25519", "ed25519+ml-dsa-65", "ed25519+vault-transit"}. Conformance layer
    test_wire_format.py verifies this on every installation.
  Note: Principle signing + conformance suite address behavioral supply chain. Full SBOM and Trusted Publishing in Phase 9.

~ ASI09: Unbounded Resource Consumption
  Coverage: PARTIAL
  Barriers: Barrier 5: Provenance
  • GOVERN action limits (Cedar context: resource_count, cost_estimate)
  • Session timeout → CommitType.TIMEOUT → veto-as-default
  • TSA circuit breaker — TSA failures don't block operations
  Note: Cedar context can carry resource limits for GOVERN evaluation. Configurable limits are a Phase 7+ enhancement.

~ ASI10: Rogue / Uncontrolled Agent Spawning
  Coverage: PARTIAL
  Barriers: Barrier 5: Provenance
  • L1-L5 autonomy enforcement — spawn requests require govern_approve
  • A2A v1.0 interceptor — all agent spawns signed and chained (Phase 6)
  • Sigchain — every agent action recorded and verifiable
  • v0.6.0: AevumOTelBridge makes agent spawn events visible as OTel spans in
    real time. Operators can configure span-based alerts in Grafana, Datadog,
    or Honeycomb to detect unexpected spawn patterns before the sigchain is
    reviewed post-hoc.
  Note: L1-L5 enforcement addresses spawn control. Full A2A interception in Phase 6.
