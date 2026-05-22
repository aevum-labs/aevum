# Aevum Maintenance Playbook — Public Summary

This document describes the methodology that governs how Aevum is maintained.
The full operating manual is maintained privately by the core team.
This document describes the philosophy.

---

## What the methodology is

Aevum's maintenance methodology has four defining principles:

**Investigation gate.** No work begins without a structured gate that
establishes what the last claim was, what evidence supports it, and what
evidence would falsify it. The gate prevents incremental drift — where each
small change seems safe but the composition is not.

**Inside-out.** Changes start from the innermost invariant layer and move
outward. Barriers first. Sigchain second. Policy layer third. Adapters last.
An invariant cannot be changed by a layer above it.

**Known unknowns.** `KNOWN_UNKNOWNS.md` is a first-class document, not a
backlog. It lists the things we know we do not know — gaps in test coverage,
unsupported platforms, unverified integrations. A known unknown is always
preferable to an unknown unknown.

**Automation bias awareness.** Every consequential checkpoint includes an
explicit automation bias warning citing the ICLR 2025 finding (84.30%
mixed-attack success; humans correct ~50% under automation bias). The warning
is mandatory, non-suppressible, and documented in standing rule S-15.

---

## Why each principle exists

The three principle tiers in `principles.yaml` explain why:

| Tier | Description | Examples |
|---|---|---|
| Immutable | Cannot be changed. Ever. By anyone. Forking the project is the only mechanism. | Crisis barrier, append-only audit trail, mandatory GOVERN checkpoint |
| Regulated | Requires a documented M-of-N ceremony to modify. Changes recorded in the signed principles chain. | Consent model, provenance requirement, minimum-necessary context |
| Operational | Standard change management — document and communicate. | Humility, openness, dignity |

Immutable principles are hardcoded in `barriers.py`. They are not policy,
not configuration, and not overridable by any engine. This is intentional:
a policy that can be turned off is not a barrier.

Regulated principles require ceremony because the ceremony is the control.
Changing how consent works without a recorded, witnessed process would itself
be a consent violation.

---

## How the maintenance cycle works

The maintenance cycle has two anchor phases per cycle:

**Phase 0 — Verify last claims.** Before adding anything, verify the claims
made in the previous cycle. What did we say was true? Is it still true?
This phase exists to prevent the cycle from becoming a sequence of
unverified additions.

**Phase 7 — Known unknowns.** The last phase of every cycle updates
`KNOWN_UNKNOWNS.md`. What is new and unknown? What was previously unknown
and is now known? Gaps are not failures — undocumented gaps are.

Between Phase 0 and Phase 7, the cycle proceeds inside-out:
barriers → sigchain → policy → adapters → documentation.

---

## How to contribute

See [CONTRIBUTING.md](CONTRIBUTING.md) for the contribution process.

Key constraints:

- **L-scope changes** (barriers.py, sigchain format, new packages, public API
  surface) require a minimum 24-hour waiting period between commit and merge,
  documented in `GOVERNANCE.md`.
- **Every PR** must complete the briefing template in
  `.github/PULL_REQUEST_TEMPLATE.md` — including the six-checkbox
  acknowledgment block.
- **Security disclosures** go to
  [GitHub Security Advisories](https://github.com/aevum-labs/aevum/security/advisories/new)
  (private disclosure only).

---

*Apache-2.0 license. See [LICENSE](LICENSE).*
