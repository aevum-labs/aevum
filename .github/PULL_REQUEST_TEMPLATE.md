<!--
  AEVUM STRUCTURED BRIEFING — p3-09 / p3-10
  Every PR that touches aevum-labs/aevum must complete this template.
  The maintainer must explicitly acknowledge each checklist item before merging.
  Clicking Merge without checking the boxes does not constitute acknowledgment.

  ICLR 2025 finding: 84.30% mixed-attack success; humans correct ~50% under
  automation bias. This briefing is the friction that makes independent review happen.
-->

## ⚠ AUTOMATION BIAS REMINDER
AI systems can be confidently wrong. Read each section independently before
checking any box. Do not merge if you have any doubt — veto is the correct outcome
when something feels off.

---

## Structured Briefing

### Intent
<!-- What does this change do? One paragraph, in plain language. -->


### Lineage
<!-- Which phase / item / issue does this implement?
     e.g. "Phase M p3-11 — EU AI Act Article 14 oversight fields"
     If this is not tied to a plan item, explain why the change is being made. -->


### Permissions
<!-- What access does this change require or extend?
     e.g. new env vars, new network endpoints, new file paths, new Cedar/OPA rules,
     new PyPI dependencies, new CI secrets. List "none" if truly none. -->


### Blast Radius
<!-- What breaks if this change is wrong?
     Be specific: which packages, which users, which data, which invariants.
     Include whether the failure would be silent or loud. -->


### Rollback
<!-- How do you undo this in under 5 minutes?
     e.g. "revert commit X, run uv sync, redeploy"
     If rollback requires a migration or is non-trivial, say so explicitly. -->


---

## Checklist Acknowledgment

The maintainer must check each box individually. These are not implied by merge.

- [ ] **Intent** — I have read and understood what this change does.
- [ ] **Lineage** — I have verified this implements the described plan item (or confirmed it is out-of-band and intentional).
- [ ] **Permissions** — I have reviewed every new permission or dependency this change introduces.
- [ ] **Blast radius** — I have considered what breaks if this change is wrong and I accept the risk.
- [ ] **Rollback** — I know how to undo this change in under 5 minutes.
- [ ] **Automation bias** — I have formed an independent judgment. I am not approving because an AI system suggested I should.

---

## Test and Quality Gate

- [ ] `uv run pytest packages/ --tb=short -q | tail -3` — all passing
- [ ] mypy clean on affected packages
- [ ] ruff clean
- [ ] Conformance suite 74/74 passing (if aevum-core or aevum-conformance changed)
- [ ] CHANGELOG.md updated under [Unreleased]

---

## Brain Test / Machine Test

**Brain Test:** Does this preserve contextual flow and accumulated awareness? Does the system still know what it knew?

**Machine Test:** Is this interface clean enough that a stranger could swap this component without reading its internals?

Both must pass. Answer each in one sentence:

Brain: 
Machine: 
