# Aevum Governance

## Overview

Aevum is an open source project maintained by its contributors. This document
describes how decisions are made, how maintainers are selected, and how the
project evolves over time.

## Maintainers

The current maintainer list is in [MAINTAINERS.md](MAINTAINERS.md). Maintainers
are responsible for reviewing and merging pull requests, managing releases, and
stewarding the project's technical direction.

A decision requires consensus among maintainers. Any maintainer may veto a
proposed change by stating their objection clearly and in writing. Vetoes must
be accompanied by a rationale. A veto is not permanent — it opens a discussion
that must be resolved before the change proceeds.

## Decision Making

**Day-to-day decisions** (bug fixes, documentation, dependency updates) are made
by any maintainer via pull request approval. One approval is sufficient.

**Significant decisions** (new public API surface, new dependencies, architectural
changes) require an RFC. Open an issue with the `rfc` label and allow 7 days for
maintainer discussion before merging.

**Frozen decisions** are listed in the master plan (CLAUDE.md). These cannot be
changed without a formal RFC and unanimous maintainer approval.

## RFC Process

1. Open an issue with the title `RFC: <description>` and the `rfc` label.
2. Describe the problem, the proposed change, and the alternatives considered.
3. Allow at least 7 calendar days for discussion.
4. If no maintainer objects after 7 days, the RFC is approved.
5. If a maintainer objects, discussion continues until resolved or the RFC is
   withdrawn.

## Adding Maintainers

Any contributor with a sustained record of quality contributions may be nominated
as a maintainer. Nomination requires a pull request to MAINTAINERS.md with support
from at least one existing maintainer. If no maintainer objects within 7 days,
the nomination is approved.

## Removing Maintainers

A maintainer who has been inactive for 12 months or who requests removal will be
moved to emeritus status in MAINTAINERS.md. Emeritus maintainers retain their
contribution history but do not participate in governance decisions.

## Code of Conduct

All participants in the Aevum project are expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md). Maintainers are responsible for enforcing
it. Violations should be reported to the address in SECURITY.md.

## Development pipeline

The tooling used to develop and maintain this project is operated as a private
internal system. The public artifact of this project is the kernel and its
release artifacts — the packages, compliance documentation, conformance suite,
and signed releases published to PyPI. The internal development pipeline is not
part of the open-source project and is not subject to the governance terms above.

## Reviewer Rotation Policy — p3-12

Aevum is currently maintained by a single person. The following self-review
policy applies until a second active maintainer is added.

### Self-review policy (solo project)

**L-scope changes** (large: new packages, major architectural changes, new public
API surface, new external dependencies, changes to barriers.py or the sigchain
format) require a minimum 24-hour waiting period between committing and merging.
This waiting period exists to allow independent re-evaluation with fresh eyes and
to reduce automation bias — the risk that an AI-assisted change is approved
immediately without genuine human review.

**S-scope and M-scope changes** (small and medium) have no mandatory waiting
period but must still pass the structured briefing checklist in the PR template.

**What counts as L-scope:**
- Any change to `barriers.py` (unconditional barriers)
- Any change to the sigchain format (new mandatory fields, field removals)
- Any new PyPI package or new external dependency
- Any change to the five public function signatures
- Any change to Cedar policy files that adds or removes a Barrier
- Any new named graph URI

**Enforcement:** This policy is documented, not code-enforced. Solo project
means trust is self-imposed. Record compliance in the PR description under
Lineage ("L-scope: 24h wait observed — committed YYYY-MM-DD, merging YYYY-MM-DD").

**When a second maintainer joins:** Replace this section with a two-reviewer
policy and remove the 24h waiting period requirement.

## Amendments

This document may be amended by pull request with approval from all active
maintainers.
