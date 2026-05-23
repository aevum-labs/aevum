# Regression Baseline — v0.6.0

This directory is the v0.6.0 regression baseline per
standing rule S-16. Any v0.7.0 session must read this
file before touching any code.

## Baseline numbers

- Tests: 1104 passed, 100 skipped
- Conformance: 74/74
- Packages: 13, all at v0.6.0
- Cedar p99: 496µs at 1000 rps
- DX timing: 9.9s (pip install to first signed sigchain entry)
- OTel bridge latency overhead: < 0.5ms p99

## Regression rule

If any benchmark, conformance test, or compat entry
regresses from these numbers in v0.7.0, treat it as a
blocking issue requiring an explicit ADR before proceeding.

## Adapter compatibility (v0.6.0)

See compat-matrix-v0.6.0.md in this directory.

## Adversarial probes (v0.6.0)

See adversarial-probes.md in this directory.
All G-11 through G-16 probes: PASS.
