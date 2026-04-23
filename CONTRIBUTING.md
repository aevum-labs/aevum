# Contributing to Aevum

Thank you for your interest in contributing. This document explains how to get
involved.

## Before You Start

**Discuss before you code.** For anything beyond a clear bug fix, open an issue
first. This prevents wasted effort and ensures your contribution aligns with
the project's direction. The [Non-Goals](NON-GOALS.md) document is the scope
fence — read it before proposing new features.

**Read the master plan.** `CLAUDE.md` contains the complete architectural
decisions, naming conventions, and frozen invariants. Contributions that
contradict frozen decisions will not be merged.

## Developer Certificate of Origin

All contributions must be signed off under the
[Developer Certificate of Origin (DCO)](https://developercertificate.org/).
This certifies you have the right to submit the contribution under the
Apache-2.0 license.

Sign off by appending the following to each commit message:

    Signed-off-by: Your Name <your.email@example.com>

With git, use `git commit -s` to add this automatically.

We use DCO rather than a CLA because it is lower friction and places the legal
responsibility appropriately on each contributor.

## Development Setup

    # Clone the repository
    git clone https://github.com/aevum-labs/aevum.git
    cd aevum

    # Install uv if you don't have it
    curl -LsSf https://astral.sh/uv/install.sh | sh

    # Install all packages in development mode
    uv sync

    # Run the test suite
    uv run pytest

    # Run the linter
    uv run ruff check .

    # Run the type checker
    uv run mypy .

## Pull Request Process

1. Fork the repository and create a branch from `main`.
2. Make your changes. Keep commits small and focused.
3. Ensure all tests pass: `uv run pytest`
4. Ensure linting passes: `uv run ruff check .`
5. Ensure type checking passes: `uv run mypy .`
6. Sign off all commits with `git commit -s`.
7. Open a pull request against `main` with a clear description.

CI must pass before any pull request can be merged. The conformance workflow
is mandatory for changes to `aevum-core` and cannot be bypassed.

## Code Standards

- **Python 3.11 minimum.** Use modern syntax: `X | Y` unions, `match` statements,
  `asyncio.TaskGroup`.
- **Strict typing.** All public functions must have complete type annotations.
  `mypy --strict` must pass with zero errors.
- **No `Any` without justification.** If you use `Any`, add a comment explaining
  why it cannot be avoided.
- **No bare exceptions.** Catch specific exception types. Use the exception
  hierarchy in `aevum.core.exceptions`.
- **Naming conventions** are in `CLAUDE.md` Section 1. They are not negotiable.

## Reporting Bugs

Open an issue with a minimal reproducible example. Include the version of
`aevum-core` and Python you are using.

## Proposing Features

Open an issue with the `rfc` label. See [GOVERNANCE.md](GOVERNANCE.md) for the
RFC process. Features that conflict with [NON-GOALS.md](NON-GOALS.md) will not
be accepted regardless of implementation quality.
