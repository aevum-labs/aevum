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

## Amendments

This document may be amended by pull request with approval from all active
maintainers.
