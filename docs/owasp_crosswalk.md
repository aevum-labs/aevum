# OWASP Agentic Top 10 — Aevum Crosswalk

**Reference:** OWASP Top 10 for Agentic Applications (2026), identifiers ASI01–ASI10.

Aevum is **primarily a detective, evidentiary control**: for most of these risks it does
not prevent the attack at runtime — it makes the attack **detectable, attributable, and
reconstructable** after the fact. A subset of categories are additionally **gated** on the
governed path by the unconditional barriers (consent, classification ceiling, crisis).
Aevum does not prevent runtime code execution, sandbox tools, issue agent identities,
encrypt inter-agent transport, or provide circuit-breaking.

The authoritative, machine-readable version of this mapping is produced by
`aevum.core.compliance.owasp_crosswalk.render_crosswalk()` and served at `GET /compliance/owasp`.

| ID | Risk (OWASP 2026) | Aevum role | What Aevum does — and does not do |
|---|---|---|---|
| ASI01 | Agent Goal Hijack | Detective | Every resulting action is recorded in the tamper-evident sigchain, so hijacked behavior is detectable and reconstructable. Aevum does not prevent goal hijack at runtime. |
| ASI02 | Tool Misuse and Exploitation | Gate + detective | Consent and the Classification Ceiling gate governed actions lacking a valid grant or exceeding clearance; the trifecta Cedar policy blocks the untrusted-read + private-read + exfiltrate composition; every invocation is recorded. Aevum does not sandbox tool execution. |
| ASI03 | Identity and Privilege Abuse | Detective | Principal and full delegation chain are recorded on every action, so identity and privilege use is auditable and tamper-evident. Aevum does not issue or scope agent identities. |
| ASI04 | Agentic Supply Chain Vulnerabilities | Detective (partial) | Source-level provenance and chain-of-custody are recorded for ingested data. Aevum is not a supply-chain scanner. |
| ASI05 | Unexpected Code Execution (RCE) | Not prevented | Aevum is an evidence and governance layer, not a code-execution sandbox; it does not prevent RCE. The action trail supports post-incident forensics. |
| ASI06 | Memory and Context Poisoning | Detective + integrity | Items entering the governed context are recorded with provenance and cryptographic integrity, so altered or poisoned context is detectable. Aevum does not judge content as malicious at ingest. |
| ASI07 | Insecure Inter-Agent Communication | Detective (partial) | Inter-agent actions passing through the kernel are recorded in the tamper-evident trail. Aevum does not encrypt or authenticate the transport itself. |
| ASI08 | Cascading Failures | Detective | The ordered, tamper-evident trail lets investigators reconstruct how a failure propagated across steps and agents. Aevum does not provide circuit-breaking. |
| ASI09 | Human-Agent Trust Exploitation | Gate + detective | The Govern human checkpoint is an auditable approval gate; review and override decisions are recorded. Aevum does not detect social engineering of the human reviewer. |
| ASI10 | Rogue Agents | Detective | Tamper-evident recording of every governed action makes rogue or out-of-scope behavior detectable and attributable; the Classification Ceiling blocks above-clearance actions. |

*OWASP® is a registered trademark of the OWASP Foundation, Inc. This page references the OWASP Top 10 for Agentic Applications descriptively; it does not imply endorsement or certification. See [Regulatory Alignment](compliance/regulatory-alignment.md) for what Aevum does and does not claim.*
