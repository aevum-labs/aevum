---
description: "Enterprise evaluation package: security architecture, threat model, deployment guide, and license analysis for procurement and security teams."
---

# Enterprise Evaluation Package

This package provides the information an enterprise security and procurement
team needs to evaluate Aevum for production deployment.

## What's in this package

| Document | Purpose |
|---|---|
| [Security Architecture](security-architecture.md) | How Aevum handles authentication, authorization, encryption, and isolation |
| [Security FAQ](security-faq.md) | Common security questions and direct answers |
| [Threat Model](threat-model.md) | What Aevum protects against and its acknowledged limits |
| [Production Deployment](deployment-guide.md) | Architecture, sizing, and operational guidance |
| [License Analysis](license-analysis.md) | License obligations for Aevum and its dependencies |

## Summary for executives

Aevum is a self-hosted Python library. There is no SaaS component, no
data transmission to Anthropic or any third party, and no licensing server.
Your data never leaves your infrastructure.

The key security properties:

- **Cryptographic audit trail** — Ed25519-signed, SHA3-256-chained log of every AI operation
- **Consent enforcement** — no agent can access data without an active, specific consent grant
- **Human review gates** — irreversible actions require explicit human approval
- **Tamper detection** — any modification to the audit trail is detectable
- **Fail closed** — when external dependencies (OPA) are unavailable, operations are denied

## Summary for security teams

- Authentication: delegated to your OIDC provider via `aevum-oidc`
- Authorization: Cedar (in-process) + OPA (optional HTTP sidecar)
- Data at rest: encrypted by your storage layer (PostgreSQL TLS, Oxigraph file encryption)
- Data in transit: TLS via your reverse proxy or load balancer
- Key management: Ed25519 keys are generated at startup; production deployments should use your KMS
- Dependencies: all Apache-2.0, MIT, or BSD licensed (see [License Analysis](license-analysis.md))

## How to proceed

1. Read the [Security Architecture](security-architecture.md) — 20 minutes
2. Review the [Threat Model](threat-model.md) — 15 minutes
3. Send security questions to [GitHub Security Advisories](https://github.com/aevum-labs/aevum/security/advisories/new) (private)
4. Follow the [Production Deployment](deployment-guide.md) guide — 1-2 engineer-days

## Commercial support

Commercial support, SLA agreements, and custom integration engineering
are on the roadmap. Contact the maintainers via
[GitHub Discussions](https://github.com/aevum-labs/aevum/discussions)
for current options.
