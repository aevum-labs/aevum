# Contributing to Aevum

## Install (users)

```
pip install aevum-core                  # core loop, SQLite, CLI
pip install "aevum-core[server]"        # + FastAPI + OIDC
pip install "aevum-core[mcp]"           # + FastMCP gateway
pip install "aevum-core[all]"           # everything
```

Note: `pip install aevum` does not install this project.
The main package is `pip install aevum-core`.

## The Machine Test and Brain Test

Every contribution must pass both tests from the Crossover Contract:

**BRAIN TEST:**
Does this preserve contextual flow and accumulated awareness?
Does the system still know what it knew?

**MACHINE TEST:**
Is this interface clean enough that a stranger could swap this component
without reading its internals?

Both must pass. Explain your answers in the PR description.

## The Five Absolute Barriers

These behaviors cannot be relaxed by any contribution.
A PR that weakens any of these will not be merged.

1. Crisis content triggers an absolute barrier — runs before everything
2. GOVERN checkpoint cannot be bypassed or made optional
3. REMEMBER must fire on every session close without exception
4. Uncertainty is mandatory in every ContextBundle output
5. Audit trail is append-only — no UPDATE or DELETE on event records

## Standing Rules

All contributors must follow the standing rules documented in the phase handoffs.
Key rules:

- Never include `tests/__init__.py` (Rule 01)
- Run mypy per-package: `mypy --package aevum.X` (Rule 02)
- Build backend is hatchling only (Rule 06)
- No `__init__.py` in `src/aevum/` (Rule 07)
- New dependencies: Apache-2.0, MIT, BSD-2, BSD-3, or ISC only

## Development Setup

```bash
git clone https://github.com/aevum-labs/aevum
cd aevum
uv sync
uv run pytest
uv run mypy --package aevum.core --config-file packages/aevum-core/pyproject.toml
```

## Pull Request Process

1. Open an issue for non-trivial changes before starting
2. All 260+ tests must pass
3. mypy must pass per-package (strict mode)
4. ruff must pass with zero warnings
5. Brain Test + Machine Test answers in PR description
6. No new external dependencies without justification
7. Code, tests, and docs change in the same commit

## Ways to Contribute

- **Bug reports:** [Open an issue](https://github.com/aevum-labs/aevum/issues)
- **Feature requests:** [Start a discussion](https://github.com/aevum-labs/aevum/discussions)
- **Security vulnerabilities:** security@aevum.build (private — do not open a public issue)
- **Pull requests:** Follow the process above

## Contact

Security issues: security@aevum.build
Bugs: GitHub Issues
Features: GitHub Discussions
