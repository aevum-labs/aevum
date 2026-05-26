# cedarpy Compatibility and Fork-Readiness

## Why cedarpy is optional

cedarpy is a community-maintained Python binding for AWS Cedar.
It is not AWS-supported. Aevum treats it as optional rather than a
hard dependency to avoid a single point of failure on the policy path.

## Currently pinned version

cedarpy 4.8.1 (verified in uv.lock as of v0.7.0).
All policy tests run against this version.

## Known compatibility constraints

- cedarpy 4.x API uses plain dicts (not AuthorizationRequest objects).
  The 3.x → 4.x migration required changes to `is_authorized()` call signature.
- Cedar language version: Aevum policies use Cedar 3.x syntax.
  cedarpy 4.x supports Cedar 3.x.
- Upgrading cedarpy: run `uv run pytest packages/aevum-core/tests/` after
  any version bump. The Cedar policy tests will catch syntax regressions.

## Forking cedarpy

If cedarpy becomes unmaintained or incompatible, fork and replace as follows:

1. Fork cedarpy on GitHub
2. Update `packages/aevum-core/pyproject.toml` `[cedar]` extra:
   ```
   cedar = ["cedarpy-fork @ git+https://github.com/YOUR_ORG/cedarpy-fork"]
   ```
3. The `CedarPolicyEngine` import guard (`try: import cedarpy`) will work
   with any package that exports the same `is_authorized()` function.
4. Run: `uv run pytest packages/aevum-core/tests/` to verify.

## OPA fallback

See `packages/aevum-core/src/aevum/core/policies/rego/` for Rego equivalents
of every Cedar policy. Set `AEVUM_OPA_URL` to use OPA instead of Cedar.

`OPAPolicyEngine` implements the full `PolicyEngine` Protocol and routes
all barrier decisions to OPA via HTTP sidecar:

| Action prefix        | Rego package                     |
|---|---|
| `consent::`          | `aevum/consent/allow`            |
| `classification::`   | `aevum/classification_ceiling/allow` |
| `provenance::`       | `aevum/provenance/allow`         |
| (default)            | `aevum/authz/allow`              |

## Parity tests

`packages/aevum-core/tests/test_policy_parity.py` verifies that OPA and Cedar
produce identical decisions for the same inputs (using mocked OPA).

Run: `uv run pytest packages/aevum-core/tests/test_policy_parity.py -v`

## Fail-open vs fail-closed

`OPAPolicyEngine` fails **open** on network error or non-200 response per
ADR-005: OPA is a sidecar, not a hard gate. If OPA goes down, the hardcoded
barriers (Crisis, AuditImmutability in `barriers.py`) still hold.

`PolicyBridge.evaluate_infrastructure()` fails **closed** on any error — this
is the infrastructure path where a misconfigured sidecar must not silently
permit traffic.

These are different use cases. Do not merge `OPAPolicyEngine` and `PolicyBridge`.
