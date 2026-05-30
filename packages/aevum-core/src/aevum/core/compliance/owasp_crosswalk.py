# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
OWASP Agentic Security Initiative (ASI) Top 10 compliance crosswalk.

Maps each OWASP ASI category to the Aevum mechanism(s) that address it. This is a
static, machine-readable mapping — no runtime evaluation. It drives the compliance
API endpoint (GET /compliance/owasp) so that operators can export their coverage
matrix without writing custom compliance tooling.

How to read coverage levels:
  "full"    — Aevum provides a structural, non-bypassable mechanism addressing the risk.
              The protection is always active; it cannot be disabled by configuration.
  "partial" — Aevum addresses the core risk but full coverage requires additional phases
              (e.g., A2A integration, Phase 6+) or operator-supplied complementary controls.
  "none"    — The category is not addressed in the current release.

Source: OWASP Top 10 for Agentic Systems (2025 pre-release).
Each entry's `notes` field contains the mechanism explanation for audit documentation.
"""
from __future__ import annotations

import dataclasses


@dataclasses.dataclass(frozen=True)
class OWASPEntry:
    """A single OWASP ASI category with Aevum mapping."""
    code: str
    title: str
    aevum_mechanisms: tuple[str, ...]
    aevum_barriers: tuple[str, ...]
    coverage: str
    notes: str


OWASP_CROSSWALK: tuple[OWASPEntry, ...] = (
    OWASPEntry(
        code="ASI01",
        title="Prompt Injection / Goal Hijacking",
        aevum_mechanisms=(
            "RELATE crisis barrier (Barrier 1) — blocks crisis/injection patterns before graph write",
            "Cedar TaintLabel — tracks READS_UNTRUSTED across session context",
            "GOVERN checkpoint — human review before consequential actions",
        ),
        aevum_barriers=("Barrier 1: Crisis", "Barrier 5: Provenance"),
        coverage="full",
        notes=(
            "Aevum's trifecta enforcement prevents the composition of "
            "READS_UNTRUSTED + READS_PRIVATE + CAN_EXFILTRATE, which is "
            "the mechanism by which prompt injection causes data exfiltration."
        ),
    ),
    OWASPEntry(
        code="ASI02",
        title="Insecure Tool / Plugin Use",
        aevum_mechanisms=(
            "Cedar TaintLabel entity — marks tools as CAN_EXFILTRATE",
            "Trifecta Cedar forbid policy — blocks dangerous tool composition",
            "GOVERN checkpoint — approves tool calls before execution",
        ),
        aevum_barriers=("Barrier 5: Provenance",),
        coverage="full",
        notes=(
            "Tool calls are Cedar-evaluated before execution. "
            "The trifecta policy blocks tool compositions that combine "
            "untrusted input access with private data access and exfiltration."
        ),
    ),
    OWASPEntry(
        code="ASI03",
        title="Excessive Agency / Privilege Escalation",
        aevum_mechanisms=(
            "L1–L5 autonomy enforcement via Cedar context attributes",
            "GOVERN checkpoint — non-bypassable for consequential actions",
            "Cedar forbid policies — autonomy.cedar enforces L1/L2 constraints",
        ),
        aevum_barriers=("Barrier 5: Provenance",),
        coverage="full",
        notes=(
            "L1-L5 autonomy levels are Cedar context attributes. "
            "At L1, every govern_approve requires human_checkpoint_completed. "
            "The autonomy level cannot be escalated by the agent itself."
        ),
    ),
    OWASPEntry(
        code="ASI04",
        title="Knowledge Base / Memory Poisoning",
        aevum_mechanisms=(
            "RELATE crisis barrier — intercepts injected crisis content",
            "pySHACL validation at RELATE time — validates fact structure",
            "Provenance tracking — every fact has a signed source",
            "Cedar ABAC at RELATE — checks classification and taint labels",
        ),
        aevum_barriers=("Barrier 1: Crisis", "Barrier 3: Classification"),
        coverage="full",
        notes=(
            "Facts cannot enter the knowledge graph without passing "
            "crisis detection, SHACL validation, and Cedar ABAC. "
            "Provenance is mandatory and cryptographically signed."
        ),
    ),
    OWASPEntry(
        code="ASI05",
        title="Cascading Agent Failure / Trust Chain Attacks",
        aevum_mechanisms=(
            "Sigchain with dual-sig — every session commit is signed",
            "Session Merkle root — tampering detected across agent handoffs",
            "GOVERN at each consequential step — no silent propagation",
        ),
        aevum_barriers=("Barrier 4: Audit Seal",),
        coverage="partial",
        notes=(
            "Aevum's sigchain detects tampering in replay. "
            "Full multi-agent trust chain validation requires A2A integration (Phase 6)."
        ),
    ),
    OWASPEntry(
        code="ASI06",
        title="Human-in-the-Loop Bypass",
        aevum_mechanisms=(
            "GOVERN checkpoint — structurally non-bypassable",
            "Automation bias warning — displayed at every substantive checkpoint",
            "Cedar Barrier 5 — govern_approve forbidden without human_checkpoint_completed",
            "Veto-as-default — timeout = veto, not approval",
        ),
        aevum_barriers=("Barrier 5: Provenance",),
        coverage="full",
        notes=(
            "Cedar's Barrier 5 forbid cannot be bypassed by any permit. "
            "The human_checkpoint_completed flag is set ONLY by the GOVERN "
            "implementation after actual human input is received. "
            "Timeout always results in veto, never in approval."
        ),
    ),
    # ASI07 — EchoLeak-class exfiltration: the trifecta Cedar policy is the primary control.
    # The attack requires ALL THREE of these taint labels to be simultaneously active:
    #   READS_UNTRUSTED   — the agent has consumed untrusted (injectable) input
    #   READS_PRIVATE     — the agent has accessed private subject data
    #   CAN_EXFILTRATE    — the agent has access to a tool that can send data externally
    # Cedar's forbid policy blocks the composition of all three. Blocking any single label
    # (e.g., marking the exfiltration tool as CAN_EXFILTRATE) prevents the attack without
    # blocking legitimate uses of the same tool in contexts without private data access.
    OWASPEntry(
        code="ASI07",
        title="Data Exfiltration / Leakage",
        aevum_mechanisms=(
            "Cedar TaintLabel — CAN_EXFILTRATE marks exfiltration-capable tools",
            "Trifecta Cedar forbid — blocks untrusted+private+exfiltrate composition",
            "Consent gate — navigate requires active consent for the purpose",
            "Classification ceiling — Barrier 3 blocks above-ceiling data",
        ),
        aevum_barriers=(
            "Barrier 2: Consent",
            "Barrier 3: Classification",
        ),
        coverage="full",
        notes=(
            "The trifecta policy (trifecta.cedar) is Aevum's primary "
            "defense against the EchoLeak-class exfiltration pattern. "
            "All three taint labels must be simultaneously active for "
            "the attack to succeed — Cedar prevents this composition."
        ),
    ),
    OWASPEntry(
        code="ASI08",
        title="Insecure Supply Chain / Dependency Confusion",
        aevum_mechanisms=(
            "Ed25519-signed principles — verified at boot",
            "Conformance suite — 9 invariants verified on every installation",
            "pip-audit in CI — dependency vulnerability scanning",
            "Trusted Publishing — signed PyPI wheels, no stored API keys",
        ),
        aevum_barriers=(),
        coverage="partial",
        notes=(
            "Principle signing + conformance suite address behavioral supply chain. "
            "Full SBOM and Trusted Publishing in Phase 9."
        ),
    ),
    OWASPEntry(
        code="ASI09",
        title="Unbounded Resource Consumption",
        aevum_mechanisms=(
            "GOVERN action limits (Cedar context: resource_count, cost_estimate)",
            "Session timeout → CommitType.TIMEOUT → veto-as-default",
            "TSA circuit breaker — TSA failures don't block operations",
        ),
        aevum_barriers=("Barrier 5: Provenance",),
        coverage="partial",
        notes=(
            "Cedar context can carry resource limits for GOVERN evaluation. "
            "Configurable limits are a Phase 7+ enhancement."
        ),
    ),
    OWASPEntry(
        code="ASI10",
        title="Rogue / Uncontrolled Agent Spawning",
        aevum_mechanisms=(
            "L1-L5 autonomy enforcement — spawn requests require govern_approve",
            "A2A v1.0 interceptor — all agent spawns signed and chained (Phase 6)",
            "Sigchain — every agent action recorded and verifiable",
        ),
        aevum_barriers=("Barrier 5: Provenance",),
        coverage="partial",
        notes=(
            "L1-L5 enforcement addresses spawn control. "
            "Full A2A interception in Phase 6."
        ),
    ),
)


def render_crosswalk(format: str = "text") -> str:
    """Render the OWASP crosswalk as human-readable text or JSON."""
    if format == "json":
        import json as _json
        entries = [
            {
                "code": e.code,
                "title": e.title,
                "aevum_mechanisms": list(e.aevum_mechanisms),
                "aevum_barriers": list(e.aevum_barriers),
                "coverage": e.coverage,
                "notes": e.notes,
            }
            for e in OWASP_CROSSWALK
        ]
        return _json.dumps({"owasp_agentic_top_10_crosswalk": entries}, indent=2)

    lines: list[str] = [
        "AEVUM — OWASP Agentic Security Initiative Top 10 Crosswalk",
        "=" * 65,
        "",
    ]
    for entry in OWASP_CROSSWALK:
        coverage_marker = "✓" if entry.coverage == "full" else "~"
        lines.append(f"{coverage_marker} {entry.code}: {entry.title}")
        lines.append(f"  Coverage: {entry.coverage.upper()}")
        if entry.aevum_barriers:
            lines.append(f"  Barriers: {', '.join(entry.aevum_barriers)}")
        for mechanism in entry.aevum_mechanisms:
            lines.append(f"  • {mechanism}")
        lines.append(f"  Note: {entry.notes}")
        lines.append("")
    return "\n".join(lines)
