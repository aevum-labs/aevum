# Aevum Policy Architecture — Cedar + OPA

*This document specifies the policy architecture for Aevum's configurable
policy layer. It is distinct from the unconditional barriers, which are
hardcoded in `barriers.py` and not governed by this specification.*

---

## G-25 Resolution: Cedar and OPA Are Complementary, Not Competing

Aevum's policy layer uses two engines for different decision domains.
Cedar handles **entity-based access control in-process**: given a principal,
an action, and a resource entity, can this operation proceed? Cedar evaluates
these decisions using typed entity graphs and formal policy statements in
`cedarpy` — within the Aevum process, with zero network round-trips. OPA
handles **content-based policy via HTTP sidecar**: given the payload of an
ingest or query operation, does it satisfy structural rules (HIPAA
minimum-necessary, GDPR purpose limitation, PCI DSS cardholder scope)?
OPA evaluates Rego bundles that the operator provides, reached via
`AEVUM_OPA_URL`. Neither engine replaces the other: Cedar's formal
authorization semantics are not Turing-complete and cannot express arbitrary
payload inspection; OPA's Rego can express arbitrary payload rules but has
no native entity-graph model for principal-resource relationships. A Cedar-only
deployment is supported and covers the five unconditional barriers and all
ABAC decisions. An OPA sidecar is optional and adds content-layer policy.
Disabling OPA does not weaken the barriers or Cedar authorization.

---

## Decision Layers

| Layer | Engine | Handles | Required? |
|---|---|---|---|
| Unconditional barriers | `barriers.py` | Crisis, classification ceiling, consent, audit seal, provenance | Always — not overridable |
| Entity ABAC | Cedar (`cedarpy`, in-process) | Principal → action → resource authorization; L1–L5 autonomy | Optional; falls back to NullPolicyEngine |
| Content policy | OPA (HTTP sidecar, Rego) | Payload inspection: HIPAA, GDPR, PCI, custom rules | Optional; no-op when `AEVUM_OPA_URL` is unset |

## Interaction Model

Aevum evaluates policy in layer order:

1. **Barriers** — synchronous, in-process, unconditional. Any barrier failure
   halts the operation immediately. No policy engine is consulted.

2. **Cedar** — synchronous, in-process ABAC. Evaluated after barriers for
   `ingest`, `query`, `review`, and `replay` calls. Cedar decisions are
   `PERMIT` or `DENY`. If cedarpy is not installed, `NullPolicyEngine`
   returns PERMIT and emits a one-time warning.

3. **OPA** — asynchronous-capable, HTTP sidecar. Evaluated after Cedar, only
   when `AEVUM_OPA_URL` is configured. OPA Rego receives the operation
   context and payload; it returns `allow: true/false` with optional reasons.
   OPA failures are configurable as fail-open (default) or fail-closed via
   `AEVUM_OPA_FAIL_CLOSED=1`.

This ordering ensures that unconditional barriers cannot be overridden by any
policy decision, and that Cedar entity decisions are resolved before OPA
inspects payload content.

## PolicyEngine Protocol

Any object satisfying this protocol is a valid policy engine:

```python
class PolicyEngine(Protocol):
    def is_permitted(
        self,
        *,
        principal_type: str,
        principal_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        context: dict[str, object],
    ) -> bool: ...
```

The `NullPolicyEngine` returns `True` for every call and logs a warning on
first use. It is suitable only for development (AEVUM_DEV=1) and testing.

## Related Documents

- ADR-005: Externalised Cedar+OPA policy layer
- `packages/aevum-core/src/aevum/core/policies/` — Cedar policy bundles
- KNOWN_UNKNOWNS.md — G-25 (resolved)
- THREAT_MODEL.md — policy layer trust assumptions
