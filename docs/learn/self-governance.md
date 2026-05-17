# How Aevum Governs Itself

Aevum provides cryptographically auditable, policy-governed AI agent
execution. The most credible demonstration of that claim is governing its
own development. Every change to Aevum — every security patch, every
protocol update, every enhancement — flows through Aevum's own governed
pipeline before landing in the codebase.

**Live demo:** [demo.aevum.build](https://demo.aevum.build) — see the
governance pipeline in action, replay any maintenance session, and try
the sandbox workflow.

**Source:** [aevum-labs/aevum-maintainer](https://github.com/aevum-labs/aevum-maintainer)

---

## Architecture

`aevum-maintainer` is a reference application built on top of Aevum that
governs the monthly maintenance workflow. It is a separate repository —
not part of the Aevum monorepo — because it demonstrates what adopters
build on top of Aevum, not what Aevum itself provides.

Aevum's five governed functions map directly onto the maintenance workflow:

```
GitHub Actions (scan results)
    │
    ▼  ingest() — OIDC-verified provenance
  Sigchain ──────────────────────────────────────────┐
    │                                                 │
    ▼  query() via MCP                                │
  Claude (research session)                           │
    │ Research Report                                 │
    ▼                                                 │
  Maintainer approval                                 │
    │  review() + commit() → consent receipt          │
    ▼                                                 │
  Claude Code (execution)                             │
    │ A2A v1.0 task (consent receipt embedded)        │
    ▼                                                 │
  Changes applied to codebase ─────────────────────► │
                                                      │
  Any future auditor ──── replay() ──────────────────┘
                          cryptographic proof
```

### The four principals

Each principal has exactly the permissions Cedar grants it — no more:

| Principal | Permitted actions |
|---|---|
| `github_actions` | `ingest(scan_results)` only — OIDC-verified |
| `research_agent` (Claude) | `query(sigchain)`, `ingest(research_findings)` |
| `execution_agent` (Claude Code) | `execute(approved_task)` — consent receipt required |
| `maintainer` | All actions including constitutional operations |

### The five absolute barriers

These are compiled-in invariants in `aevum-maintainer`. Cedar policies
can further restrict — they cannot relax these:

| Barrier | Effect in the maintenance pipeline |
|---|---|
| **Crisis** | Halts any action flagged as threatening project integrity |
| **Classification Ceiling** | Cedar limits which data each principal can access |
| **Consent** | No execution agent task without a sigchain-verified consent receipt |
| **Audit Immutability** | Sigchain entries cannot be modified after commit |
| **Provenance** | Every ingest requires OIDC-verified provenance claims |

---

## The Monthly Maintenance Workflow

The workflow runs automatically on the 1st of every month:

1. **GitHub Actions** runs `pip-audit` and a dependency freshness scan.
   Results are committed to `maintenance/scan_results.md` in the repo.
   This triggers `aevum-maintainer`'s ingest endpoint, which verifies
   the GitHub OIDC token and writes a sigchain entry with the scan data
   and its provenance.

2. **Claude** (research session) queries the sigchain via the MCP
   research interface — 6 read-only tools, Cedar-gated, every call
   logged as an audit entry. Claude produces a Research Report
   classifying findings by severity.

3. **The maintainer** reviews the Research Report and approves the
   proposed actions. This approval is captured as a consent receipt in
   the sigchain — a `commit()` entry signed with the maintainer's
   identity, linking back to the scan data that justified it.

4. **Claude Code** receives an A2A v1.0 task containing the consent
   receipt hash in a `DataPart`. The `verify-task` CLI checks the hash
   against the sigchain before any action is taken. Without a valid
   consent receipt, execution is blocked by the Consent barrier.

5. **Any future auditor** can run `GET /v1/replay/{session_id}` against
   the `aevum-maintainer` API to retrieve every action in a session,
   verify the cryptographic chain, and confirm that human consent
   preceded every execution.

---

## EU AI Act Article 12 Demonstration

Article 12 of the EU AI Act requires that high-risk AI systems
"technically allow for the automatic recording of events (logs) over
the lifetime of the system," supporting three purposes:

- **(a)** identifying situations that may result in risk
- **(b)** facilitating post-market monitoring
- **(c)** monitoring operation by deployers

The `aevum-maintainer` sigchain satisfies all three for its own
maintenance pipeline:

- **Automatic recording:** every scan, research query, consent decision,
  and execution is written to the sigchain automatically — no manual
  export required.
- **(a) Risk identification:** `review` entries record what was flagged
  and the maintainer's risk assessment.
- **(b) Post-market monitoring:** `replay` entries provide a verifiable
  reconstruction of any session.
- **(c) Deployer oversight:** consent entries prove that a human reviewed
  and approved each action before execution.

The `GET /v1/compliance/{session_id}` endpoint produces a structured
Article 12 report for any maintenance session. Try it at
[demo.aevum.build](https://demo.aevum.build) under the Compliance tab.

!!! note "Scope of this claim"
    The maintenance pipeline is not classified as a high-risk AI system
    under Annex III of the EU AI Act. This demonstration shows that Aevum
    provides the infrastructure needed for Article 12 compliance in
    systems that *are* high-risk — and proves it works by applying the
    same controls to its own development.

---

## External Tamper Evidence

The sigchain head hash is anchored to the public record weekly via a
GitHub Actions workflow (`rekor-anchor.yml`). Anchor entries accumulate
in `maintenance/rekor_anchors.jsonl` — an append-only, git-tracked file
that provides third-party tamper evidence without requiring a running
service.

This means: even if the Fly.io deployment were compromised, the weekly
anchor entries in the public git history prove what the sigchain state
was at each anchor point.

---

## The Break-Glass Path

A self-governing system must be able to fail gracefully. If
`aevum-maintainer` itself becomes unavailable — sigchain corruption,
Cedar lockout, key loss — the `break-glass` CLI creates a bypass entry
in a separate `break_glass_log.jsonl` (not the main sigchain), returns
a signed bypass receipt, and the maintainer includes that receipt in
the manual PR description as an audit trail of the bypass.

The break-glass path is documented, tested, and exercised before each
major release. See the
[aevum-maintainer break-glass docs](https://github.com/aevum-labs/aevum-maintainer/blob/main/docs/break-glass.md)
for the full procedure.

---

## Progressive Autonomy

The trust ratchet tracks consecutive approved actions by class. After
10 consecutive approvals of the same action class (e.g. `dep_bump`)
with no modification, the system proposes promotion to `auto_window` —
automatic execution with a 24-hour undo window.

Promotion requires an explicit maintainer decision — it is never
automatic. Demotion happens automatically on any override or Crisis
trigger. Policy changes, schema changes, and key rotations are hardcoded
as always requiring human approval — they cannot be promoted.

This implements the EU AI Act Article 14 human oversight requirement:
the *ability* to monitor, intervene, and halt is always preserved even
as routine actions become more automated.

---

## OWASP Agentic AI Top 10 Coverage

| OWASP Risk | Aevum Barrier | Mechanism |
|---|---|---|
| ASI01 Agent Goal Hijack | Consent | No task executes without a sigchain-verified consent receipt |
| ASI02 Tool Misuse | Classification Ceiling | Cedar limits which tools each principal can invoke |
| ASI03 Identity/Privilege Abuse | Provenance | OIDC-verified principal identity on every sigchain entry |
| ASI04 Resource Overuse | Crisis | Crisis barrier halts any flagged action immediately |
| ASI05 Data Privacy Breach | Classification Ceiling | Cedar enforces data compartmentalization |
| ASI06 Cascading Hallucination | Consent + Audit | Human approval required; immutable audit trail |
| ASI07 Intent Misalignment | Consent | Proposed action is human-readable and human-approved |
| ASI08 Context Manipulation | Audit Immutability | Sigchain entries cannot be modified after commit |
| ASI09 Rogue Agent Behavior | Consent + Provenance | Verified identity and consent receipt required to act |
| ASI10 Supply Chain Exploit | Provenance + Audit | OIDC provenance on all ingested scan results |

See the [OWASP tab at demo.aevum.build](https://demo.aevum.build) for
an interactive view of how each risk was addressed in the most recent
maintenance session.

---

## See Also

- [Architecture](/learn/architecture/) — Aevum's five governed functions and five barriers
- [Audit Trails and Article 12](/concepts/audit-trails/) — compliance record-keeping
- [Standards Alignment](/learn/standards-alignment/) — regulatory and standards mapping
- [demo.aevum.build](https://demo.aevum.build) — live interactive demonstration
- [aevum-labs/aevum-maintainer](https://github.com/aevum-labs/aevum-maintainer) — source code
