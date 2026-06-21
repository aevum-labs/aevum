# ADR-012: Hybrid-by-default, fail-closed signing posture

Date: 2026-06-10
Status: Accepted — implemented in v0.8.0; v0.7.5 ships an honestly-documented interim fallback
Deciders: Aevum Labs
Confidence: High

## Context and Problem Statement

ADR-004 established a pluggable `Signer` ABC with `InProcessSigner` as the default for the
interface contract — classical Ed25519 keys generated in-process with no external dependencies.
It did not address which algorithm set the kernel should use by default, or what should happen
when the post-quantum backend is unavailable.

In practice, `Kernel.local()` already uses `DualSigner` (Ed25519 + ML-DSA-65) as the default.
But if `liboqs` is absent, `DualSigner.generate()` silently emits a `RuntimeWarning` and
falls back to Ed25519-only — without surfacing this to operators at a log level that cannot
be suppressed by a warning filter. Docstrings claimed "InProcessSigner is the default",
contradicting what `Kernel.local()` actually does.

Two problems therefore require a formal decision:

1. **Which algorithm set is the intended default?**
   The answer must be recorded as policy, not left implicit in code paths.
2. **What is the correct behaviour when the PQC backend is unavailable?**
   Silent degradation (current v0.7.5 interim) is unacceptable as a steady-state posture.

## Decision Drivers

- **NIST SP 800-53 rev 5, SA-8(23)** — Secure-by-default / deny-by-default design principle:
  systems must default to the most secure configuration available, requiring explicit operator
  action to reduce security posture.
- **FIPS 204 (effective August 2024)** — ML-DSA is the NIST-standardised module-lattice
  digital signature algorithm. Aevum sigchain entries may outlive classical cryptographic
  assumptions; ML-DSA-65 provides the mandated post-quantum safety margin.
- **NIST IR 8547 (2024 draft)** — Classical elliptic-curve and RSA algorithms are deprecated
  after 2030 and disallowed after 2035 for systems generating new signatures. Long-lived signed
  records created today must survive this transition.
- **NSA CNSA 2.0 (2022)** — Software and firmware signing leads the migration schedule;
  ML-DSA-87 must be in production "as soon as possible" and by 2030 at the latest.
- **SEC 17a-4 / FINRA Rule 4511** — Durable authenticity of records over multi-year (often
  decade-scale) retention periods. Classical signatures may not satisfy "non-erasable,
  non-rewritable" authenticity if quantum attacks materialise during the retention window.
- **"Trust now, forge later" (harvest-now, decrypt-later)** — Adversaries can store
  classically-signed records today and forge or repudiate them retroactively once quantum
  computers are available. Long-lived sigchain entries are exactly the at-risk category.
- **Silent degradation ≈ self-inflicted downgrade attack** — An operator who installs
  `aevum-core` without `[pqc]` and receives no hard error believes they have quantum-safe
  signing. They do not. The gap between expectation and reality is indistinguishable from a
  deliberate downgrade, and produces the same forensic outcome: sigchain entries that cannot
  survive a post-quantum audit.

## Considered Options

1. **Fail-closed by default; classical-only is an audited opt-in** (this decision)
2. Fail-open by default; warn loudly but continue (v0.7.5 interim — rejected as steady-state)
3. Require `[pqc]` at install time via package dependencies (rejected — breaks environments
   that cannot build liboqs from source)
4. Always classical; offer PQC as an opt-in extra (rejected — violates SA-8(23) and leaves
   the default posture below the NIST IR 8547 timeline)

## Decision Outcome

**Option 1.** The signing posture is: hybrid (Ed25519 + ML-DSA-65) by default; absence of the
PQC backend is a hard failure; classical-only is an explicit, audited operator opt-in.

### Default behaviour (v0.8.0 and later)

- `Kernel.local()` requires ML-DSA-65 to be available. If `liboqs` is absent, the kernel
  raises `SigningPostureError` at startup with a clear message directing the operator to
  install `aevum-core[pqc]` or declare `AEVUM_CLASSICAL_ONLY=1` (see below).
- ML-DSA-65 is the PQC algorithm; ML-DSA-87 (CNSA 2.0 preferred level) is available via
  `AEVUM_MLDSA_LEVEL=87` for deployments that require it.

### Classical-only opt-in (v0.8.0 and later)

An operator may set `AEVUM_CLASSICAL_ONLY=1` to run Ed25519-only. This is an **audited
degraded mode**, not a quiet fallback. On startup, the kernel:

1. Logs a `WARNING` at every boot citing this ADR and the NIST IR 8547 deprecation timeline.
2. Writes a signed degraded-mode attestation into the episodic ledger, recording the
   operator's explicit choice with a timestamp and the kernel version.
3. The attestation is verifiable and immutable — operators cannot later claim the degraded
   posture was unintentional.

### v0.7.5 interim (honest fallback)

v0.7.5 does not yet enforce fail-closed — that is v0.8.0 work. However, v0.7.5 ships the
following honesty patches so that the interim state is not silently misleading:

- `DualSigner.generate()` replaces the `RuntimeWarning` (suppressible via warning filters)
  with a `logger.warning(...)` call that is always emitted regardless of Python warning
  configuration, identifying the interim Ed25519-only state, and referencing this ADR and
  the v0.8.0 fail-closed timeline.
- Module and class docstrings in `signing.py` describe `Kernel.local()`'s actual behaviour:
  `DualSigner` is the kernel default; it signs hybrid when liboqs is present; it falls back
  to Ed25519-only **with a loud warning** when liboqs is absent (interim until v0.8.0).
- `InProcessSigner` is described accurately: the reference implementation of the `Signer`
  ABC, classical-only, not the kernel default.
- `cli.md` updated to match: `aevum init` generates Ed25519 + ML-DSA-65 when liboqs is
  present; Ed25519-only with a loud warning otherwise (interim); references this ADR.

## Positive Consequences

- Operators cannot accidentally run in classical-only mode without a log record showing they
  did so.
- The `[pqc]` installation requirement is surfaced at startup, not discovered at audit time.
- Signed records created in default mode satisfy FIPS 204, NIST IR 8547, and CNSA 2.0
  software-signing guidance.
- The classical-only opt-in path creates a forensic trail of the degraded-mode decision.

## Negative Consequences / Mitigations

- **First-run friction**: operators without `liboqs` installed will receive a hard error at
  startup (v0.8.0+). Mitigated by a clear error message with install instructions.
- **Build complexity**: `liboqs` requires a native library build. Mitigated by pre-built
  wheels for major platforms. No pure-Python ML-DSA implementation is provided.
- **v0.7.5 interim gap**: Ed25519-only fallback is not fail-closed yet. Mitigated by honest
  logging and documentation — operators know the posture is interim.

## Relationship to Other ADRs

- **Complements ADR-004**: ADR-004 governs the `Signer` interface contract (pluggability,
  trust boundary, in-process vs. external). This ADR governs the algorithm posture and the
  fail-closed default for `Kernel.local()`. Both are required; neither supersedes the other.
- **Overrides the "classical default" framing**: any docstring or documentation claiming
  "InProcessSigner is the default" in the context of `Kernel.local()` is superseded by this
  ADR. `InProcessSigner` remains the reference implementation of the `Signer` ABC for
  classical-only use cases.

## Standards Citations

| Standard | Relevance |
|---|---|
| NIST SP 800-53 rev 5, SA-8(23) | Secure-defaults / deny-by-default design |
| FIPS 204 (Aug 2024) | ML-DSA standard; ML-DSA-65 selected |
| NIST IR 8547 (2024 draft) | Classical deprecation (2030) / disallowance (2035) |
| NSA CNSA 2.0 (2022) | Software signing leads PQC migration; ML-DSA-87 by 2030 |
| SEC 17a-4 / FINRA Rule 4511 | Durable authenticity over multi-year retention |
| RFC 8032 | Ed25519 specification (retained for hybrid coverage) |
| RFC 8785 | JCS canonical serialisation for signing bytes |
