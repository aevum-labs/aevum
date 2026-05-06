# ADR-005: Externalised Cedar+OPA policy layer

Date: 2026-05-06
Status: Accepted
Deciders: Aevum Labs
Confidence: High

## Context and Problem Statement

Aevum's five absolute barriers (crisis, classification ceiling, consent,
audit immutability, provenance) are kernel-enforced and unconditional.
Everything above those barriers — which actors can query which subject data,
what purposes are allowed, what classification levels apply to which roles —
is sector-specific and must be configurable without modifying the kernel.
What is the correct architecture for the configurable policy layer?

## Decision Drivers

- Different sectors have radically different policy requirements (HIPAA
  minimum-necessary vs. PCI DSS cardholder data access vs. EU AI Act
  high-risk categories vs. trading firm access controls)
- Policy must be auditable — changes must be traceable
- Policy must be human-readable — a compliance team must be able to read it
- Policy must be testable independently of the kernel
- AWS Bedrock AgentCore uses Cedar; OPA is the de-facto standard for
  cloud-native policy; both have active communities

## Considered Options

1. **Cedar (primary) + OPA (secondary)** — both externalised
2. OPA only
3. Custom policy DSL embedded in kernel
4. YAML-based configuration files

## Decision Outcome

Option 1. Cedar is used for entity-based access control decisions (can this
actor perform this operation on this resource?). OPA/Rego is used for
content-based rules (does this payload satisfy HIPAA minimum-necessary for
this purpose?). Both are externalised — the kernel calls them, it does not
embed them.

The five absolute barriers are NOT policy-controlled. They cannot be
overridden by any Cedar or OPA policy. This is the Vault pattern: the
audit broker is unconditional; policy governs everything above it.

**cedar-for-agents** (cedar-policy organisation, Apache-2.0, April 2026)
extends Cedar with agent-specific entity types. Aevum's Cedar bundles are
compatible with this extension and should remain so.

### Consequences

**Good:** Sector-specific compliance without kernel changes; policies
auditable via version control; Cedar's formal verification properties
allow proving policy correctness; OPA's ecosystem has extensive HIPAA/PCI
bundles to adapt from.

**Bad:** Two policy engines introduce operational complexity. Mitigation:
Cedar-only deployments are possible (skip OPA URL config); OPA-only is
not supported because Cedar provides the authorization primitive.

**Residual risk:** A misconfigured Cedar policy could deny legitimate
operations. Mitigation: OPA fails open for policy-layer decisions (unlike
barriers which fail closed).

## Related ADRs

- ADR-001 (barriers are unconditional — above policy layer)
