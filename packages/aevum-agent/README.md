# aevum-agent

A2A v1.0 protocol interceptor and governance layer for Aevum.

**Status: Phase 0 skeleton. Full implementation in Phase 6.**

## Install

```
pip install aevum-agent
```

Or via aevum-core extras:

```
pip install "aevum-core[a2a]"
```

## What This Provides (Phase 6+)

- Transparent A2A v1.0 task envelope signing and chaining into the audit sigchain
- Signed Agent Cards (JWS/RFC 7515)
- OAuth 2.0 device-code flow (RFC 8628) with PKCE
- GOVERN checkpoint integration for agent task approvals
- Full audit trail: every Task, Artifact, and streaming event is Merkle-chained

## Migration from aevum-llm

```
pip uninstall aevum-llm
pip install aevum-agent
```

## A2A v1.0

Targets the Linux Foundation-ratified A2A v1.0 specification (April 2026),
not the prior v1.0.0-rc. Breaking changes from rc are handled internally.
