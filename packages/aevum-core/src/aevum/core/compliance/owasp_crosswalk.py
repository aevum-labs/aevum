# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
OWASP Agentic Security Initiative (ASI) Top 10 compliance crosswalk.

Maps each OWASP ASI category to the Aevum mechanism(s) that address it. This is a
static, machine-readable mapping — no runtime evaluation. It drives the compliance
API endpoint (GET /compliance/owasp) so that operators can export their coverage
matrix without writing custom compliance tooling.

Aevum is primarily a detective, evidentiary control: for most of these risks it does not
prevent the attack at runtime — it makes the attack detectable, attributable, and
reconstructable. A subset of categories are additionally gated on the governed path by the
unconditional barriers (consent, classification ceiling, crisis). The coverage levels below
describe EVIDENTIARY coverage, not prevention:
  "full"    — Aevum always records the governed actions relevant to this risk in the
              tamper-evident trail; the evidentiary mechanism is structural and active by
              default.
  "partial" — evidentiary coverage is conditional, scoped to actions that pass through the
              kernel, or requires complementary controls/phases.
  "none"    — the risk is outside Aevum's evidentiary scope (e.g., runtime RCE prevention).

Source: OWASP Top 10 for Agentic Applications (2026).
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
        title="Agent Goal Hijack",
        aevum_mechanisms=(
            "Tamper-evident sigchain — every resulting action is recorded",
            "replay() reconstruction of the action sequence",
        ),
        aevum_barriers=("Detective",),
        coverage="full",
        notes=(
            "Aevum does not prevent goal hijack at runtime. Every resulting action is "
            "recorded in the tamper-evident sigchain, so hijacked behavior is detectable "
            "and reconstructable after the fact."
        ),
    ),
    OWASPEntry(
        code="ASI02",
        title="Tool Misuse and Exploitation",
        aevum_mechanisms=(
            "Consent grant check on governed actions",
            "Classification Ceiling clearance gate",
            "Trifecta Cedar policy — blocks the untrusted-read + private-read + exfiltrate composition",
            "Sigchain records every invocation",
        ),
        aevum_barriers=("Gate + detective", "Barrier 3 Consent", "Barrier 2 Classification Ceiling"),
        coverage="partial",
        notes=(
            "Consent and the Classification Ceiling gate governed actions that lack a valid "
            "grant or exceed clearance; every invocation is recorded. Aevum does not sandbox "
            "tool execution itself."
        ),
    ),
    OWASPEntry(
        code="ASI03",
        title="Identity and Privilege Abuse",
        aevum_mechanisms=(
            "Principal and delegation chain recorded on every action (receipt delegated_by / delegation_scope)",
            "Tamper-evident attribution",
        ),
        aevum_barriers=("Detective",),
        coverage="partial",
        notes=(
            "Every action records the full principal and delegation chain, so identity and "
            "privilege use is auditable and tamper-evident. Aevum does not issue or scope "
            "agent identities."
        ),
    ),
    OWASPEntry(
        code="ASI04",
        title="Agentic Supply Chain Vulnerabilities",
        aevum_mechanisms=(
            "Source-level provenance and chain-of-custody recorded for ingested data",
        ),
        aevum_barriers=("Detective (partial)", "Barrier 5 Provenance"),
        coverage="partial",
        notes=(
            "Source-level provenance and chain-of-custody are recorded for ingested data, "
            "so the inputs an agent acted on are verifiable. Aevum is not a supply-chain "
            "scanner."
        ),
    ),
    OWASPEntry(
        code="ASI05",
        title="Unexpected Code Execution (RCE)",
        aevum_mechanisms=(
            "Post-incident action trail for forensics",
        ),
        aevum_barriers=("Not prevented",),
        coverage="none",
        notes=(
            "Aevum is an evidence and governance layer, not a code-execution sandbox; it "
            "does not prevent RCE. The action trail supports post-incident forensics."
        ),
    ),
    OWASPEntry(
        code="ASI06",
        title="Memory and Context Poisoning",
        aevum_mechanisms=(
            "Provenance and cryptographic integrity on items entering the governed context",
        ),
        aevum_barriers=("Detective + integrity", "Barrier 5 Provenance"),
        coverage="full",
        notes=(
            "Items entering the governed context are recorded with provenance and "
            "cryptographic integrity, so altered or poisoned context is detectable. Aevum "
            "does not judge content as malicious at ingest."
        ),
    ),
    OWASPEntry(
        code="ASI07",
        title="Insecure Inter-Agent Communication",
        aevum_mechanisms=(
            "Inter-agent actions passing through the kernel recorded in the tamper-evident trail",
            "A2A audit middleware (aevum-agent)",
        ),
        aevum_barriers=("Detective (partial)",),
        coverage="partial",
        notes=(
            "Inter-agent actions that pass through the kernel are recorded in the "
            "tamper-evident trail. Aevum does not encrypt or authenticate the transport "
            "itself."
        ),
    ),
    OWASPEntry(
        code="ASI08",
        title="Cascading Failures",
        aevum_mechanisms=(
            "Ordered, tamper-evident trail for reconstructing failure propagation across steps and agents",
        ),
        aevum_barriers=("Detective",),
        coverage="partial",
        notes=(
            "The ordered, tamper-evident trail lets investigators reconstruct how a failure "
            "propagated across steps and agents. Aevum does not provide circuit-breaking "
            "between agents."
        ),
    ),
    OWASPEntry(
        code="ASI09",
        title="Human-Agent Trust Exploitation",
        aevum_mechanisms=(
            "Govern human checkpoint — auditable approval gate",
            "Human review and override decisions recorded",
        ),
        aevum_barriers=("Gate + detective",),
        coverage="partial",
        notes=(
            "The Govern human checkpoint is an auditable approval gate, and human review and "
            "override decisions are recorded. Aevum does not detect social engineering of the "
            "human reviewer."
        ),
    ),
    OWASPEntry(
        code="ASI10",
        title="Rogue Agents",
        aevum_mechanisms=(
            "Tamper-evident recording of every governed action",
            "Classification Ceiling blocks above-clearance actions",
        ),
        aevum_barriers=("Detective", "Barrier 2 Classification Ceiling"),
        coverage="partial",
        notes=(
            "Tamper-evident recording of every governed action makes rogue or out-of-scope "
            "behavior detectable and attributable; the Classification Ceiling blocks "
            "above-clearance actions."
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
