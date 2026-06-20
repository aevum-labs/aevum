# aevum-oidc

OIDC/JWT principal-binding verifier adapter for Aevum.

Implements `aevum.core.protocols.principal_binding_verifier.PrincipalBindingVerifier`
for OIDC/JWT-shaped credentials. Given an AuditEvent's recorded v2
`principal_binding` blob (see `docs/spec/aevum-signing-v2.md`), it re-checks
that the binding is well-formed, within its validity window, from an expected
issuer, and for an expected audience.

```bash
pip install aevum-oidc
```

```python
from datetime import UTC, datetime

from aevum.oidc import OidcJwtBindingVerifier

verifier = OidcJwtBindingVerifier()
result = verifier.verify(
    {"principal_binding": event.principal_binding},
    at_time=datetime.now(UTC),
    expected_issuers=["https://idp.example"],
    expected_audience="aevum",
)

result.verified              # True / False
result.checks_performed      # e.g. ["structure", "validity_window", "issuer_match", "audience_match"]
result.checks_not_performed  # always: issuer-signature re-verification, token replay
result.failure_reasons       # human-readable reasons when verified is False
```

## HONESTY SCOPE — read this before trusting `verified=True`

This adapter verifies a RECORDED binding is well-formed, within its validity
window, from an expected issuer, and for the expected audience — a
consistency/policy check over a credential that was verified once, AT CAPTURE
TIME, by whatever committed the event (the witness model). It does **NOT**:

- re-verify the issuer's signature — the signature is never recorded; the
  recorded `principal_binding` blob is an allow-list extraction of claims
  (`iss`, `aud`, `jti`, `iat`, `exp`, `cnf.jkt`), not the original signed token;
- re-verify a bearer token — none is ever stored;
- by itself prove the named subject acted — that is a separate
  commitment-match check (`aevum.core.audit.commitment_key_store.verify_commitment`)
  that needs the deployment's commitment key, which this adapter does not hold.

Every `BindingVerificationResult` lists `checks_performed` and
`checks_not_performed` explicitly, so this scope is structural — visible on
the result object — not just documented here. `checks_not_performed` always
names issuer-signature re-verification and token replay, regardless of how the
other checks come out.

Three distinct "OIDC/identity" scopes exist in Aevum and must never be
conflated:

1. **Live-authn** — a separate, unimplemented `aevum-server` contract
   (`run(ctx, payload) -> {oidc_validated, resolved_actor}`) for validating a
   live Bearer token. This package does not implement, claim to be, or
   collide with that contract.
2. **Recorded-blob consistency verify** — this package.
3. **Commitment-match to a named identity** — `verify_commitment()` in
   `aevum-core`, needs the deployment's commitment key.

Each proves something different; none proves issuer-signature re-issuance
under v2.

## Offline-first (DD-I3)

`verify()` never makes a network call. It operates entirely on the blob
recorded at commit time plus optionally-supplied trust material (a holder JWK,
passed as `holder_jwk` at construction or per-call) used only to confirm a
recorded `cnf.jkt` thumbprint matches a specific key — never to re-verify a
signature. Evidence built this way stays verifiable years later without
needing a live JWKS endpoint to still exist.

A separate, optional convenience resolves a holder key from a live JWKS
endpoint and then delegates to the same `verify()`:

```bash
pip install aevum-oidc[jwks]
```

```python
from aevum.oidc.jwks_fetch import verify_with_live_jwks

result = verify_with_live_jwks(
    verifier, {"principal_binding": event.principal_binding},
    at_time=datetime.now(UTC),
    jwks_url="https://idp.example/.well-known/jwks.json",
    kid="key-1",
)
```

Importing `aevum.oidc` never imports PyJWT — only calling
`live_jwks_fetch()` / `verify_with_live_jwks()` does, and it raises a clear
`ImportError` with an install hint if the `jwks` extra is not installed.

## Neutrality

`handles()` declines anything that is not OIDC-shaped — including a
SPIFFE-shaped blob (`spiffe://` trust domain, no `https` `iss`) — by design,
so that `PrincipalBindingVerifier` stays a genuinely neutral interface rather
than one that quietly assumes OIDC. A future `aevum-spiffe`-side verifier
implements the same Protocol for SPIFFE-shaped bindings.

## Discovery

Registered under the `aevum.binding_verifiers` entry-point group (sibling to
`aevum.complications`, but distinct — a binding verifier is not a
complication):

```toml
[project.entry-points."aevum.binding_verifiers"]
oidc-jwt = "aevum.oidc.verifier:OidcJwtBindingVerifier"
```

## See also

- [`docs/spec/aevum-signing-v2.md`](../../docs/spec/aevum-signing-v2.md) — the
  `principal_binding` / `principal_commitment` construction this adapter
  re-verifies.
- `aevum.core.protocols.principal_binding_verifier` — the neutral Protocol.
- `aevum.core.audit.commitment_key_store.verify_commitment` — the
  issuer-neutral commitment-match check.
