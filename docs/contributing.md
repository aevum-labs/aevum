!!! note
    This page mirrors `CONTRIBUTING.md` in the repository root.
    If you find a discrepancy, the repository file takes precedence.

# Contributing to Aevum

Thank you for your interest in contributing.

## Ways to contribute

- **Bug reports:** [Open an issue](https://github.com/aevum-labs/aevum/issues)
- **Feature requests:** [Start a discussion](https://github.com/aevum-labs/aevum/discussions)
- **Security vulnerabilities:** [GitHub Security Advisories](https://github.com/aevum-labs/aevum/security/advisories/new) (private)
- **Pull requests:** See the development guide below

## Development setup

```bash
git clone https://github.com/aevum-labs/aevum.git
cd aevum
uv sync
```

## Running tests

```bash
# All packages
uv run pytest packages/

# Single package
cd packages/aevum-core
uv run pytest tests/ -v
```

## Code standards

- Python 3.11+, mypy strict, ruff (zero warnings)
- Every function has a docstring explaining purpose and constraints
- Comments explain *why*, not *what*
- No `tests/__init__.py` — test directories are not packages
- Run `uv run mypy --package aevum.<name>` per package

## Submitting a pull request

1. Fork the repository
2. Create a branch: `git checkout -b my-feature`
3. Make your changes with tests
4. Run: `uv run pytest` and `uv run mypy --package aevum.<name>`
5. Sign your commits: `git commit -s -m "Your message"`
6. Open a pull request against `main`

## Conformance

Changes to aevum-core must pass the conformance suite:

```bash
cd ../aevum-conformance
uv run pytest layer1_wire/ layer2_semantic/ layer3_invariants/ -v
```

## License

By contributing, you agree your contributions are licensed under Apache-2.0.
