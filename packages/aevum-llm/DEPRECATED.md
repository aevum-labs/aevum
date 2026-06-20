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

Full migration instructions: [docs/learn/guides/migrate-from-aevum-llm.md](../../docs/learn/guides/migrate-from-aevum-llm.md)

## Why

Every major AI framework already provides LLM integration.
aevum-llm duplicated that work without adding governance value.
aevum-agent adds governance value: it signs and chains every
A2A v1.0 task envelope, enforces the GOVERN checkpoint, and
provides audit trail for agent-to-agent communication.

## Timeline

- v0.3.0: Final feature release
- v0.3.1: This tombstone (DeprecationWarning on import)
- **v1.0: Removal target.** The package will be removed from the monorepo
  and yanked from PyPI no earlier than the v1.0 release. Until then it
  remains installable (with the `DeprecationWarning`) so pinned dependents
  are not broken without notice. This is a deprecation window, not an
  early yank — see `KNOWN_UNKNOWNS.md` (THIN / HO-SESSION5-CLOSE) for the
  decision record.
