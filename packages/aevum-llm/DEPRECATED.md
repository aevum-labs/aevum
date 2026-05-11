# aevum-llm — DEPRECATED

This package is deprecated. No further development will occur here.

## Migration

Replace aevum-llm with aevum-agent:

```
pip uninstall aevum-llm
pip install aevum-agent
```

aevum-agent provides the A2A v1.0 protocol implementation
which supersedes the LLM complication pattern.

## Why

Every major AI framework already provides LLM integration.
aevum-llm duplicated that work without adding governance value.
aevum-agent adds governance value: it signs and chains every
A2A v1.0 task envelope, enforces the GOVERN checkpoint, and
provides audit trail for agent-to-agent communication.

## Timeline

- v0.3.0: Final feature release
- v0.3.1: This tombstone (DeprecationWarning on import)
- Future: Removed from active monorepo maintenance
