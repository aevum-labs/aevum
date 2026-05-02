# FAQ

**Does Aevum send any data outside my environment?**

No. By default, nothing leaves your process. Optional complications
(`aevum-oidc`, `aevum-llm`) make outbound calls only when configured.

---

**Do I need a database to use Aevum?**

No. The default `Engine()` uses in-memory storage. For persistence,
add `aevum-store-oxigraph` (embedded) or `aevum-store-postgres`.

---

**What happens if I don't have cedarpy installed?**

The kernel warns at startup and falls back to permissive consent
decisions. The five absolute barriers still fire unconditionally —
crisis detection, classification ceiling, consent (fast-path denials),
audit immutability, and provenance are not affected.

---

**Is Aevum a SaaS product?**

No. It is a Python library. You install it and run it yourself.
Your data never leaves your infrastructure.

---

**Does aevum-mcp only work with Claude Desktop?**

No. It works with any MCP-compatible host — Claude Desktop, Cursor,
VS Code Copilot, and others. The configuration format is the same.
See [MCP Setup](mcp-setup.md).

---

**Can I use Aevum without a consent grant?**

No. Barrier 3 (Consent) blocks `ingest`, `query`, and `replay` without
an active consent grant. This is unconditional.

---

**How do I handle GDPR right-to-erasure?**

Call `engine.revoke_consent_grant(grant_id)`. The data in the knowledge
graph becomes immediately unreachable at the next operation. Physical
deletion from the storage backend is a separate step if required by your
data retention policy.

---

**Can I run Aevum on a Raspberry Pi or other low-powered hardware?**

Yes. With Oxigraph as the backend and no OPA sidecar, the memory
and CPU footprint is minimal. The sigchain operations (Ed25519,
SHA3-256) are fast on any modern hardware including ARM.

---

**Does Aevum have an SLA?**

No. It is open source software. Community support via
[GitHub Issues](https://github.com/aevum-labs/aevum/issues) and
[GitHub Discussions](https://github.com/aevum-labs/aevum/discussions).
Commercial support is on the roadmap.

---

**What is the difference between `replay` and `query`?**

`query` retrieves current data from the knowledge graph (`urn:aevum:knowledge`).
`replay` reconstructs a past ledger entry from the provenance graph
(`urn:aevum:provenance`). They read from different places and return
different things. See [The Five Functions](../concepts/five-functions.md)
for the full distinction.

---

**Can multiple agents share the same Engine instance?**

Yes, with different `grantee_id` values in their consent grants.
Each agent's access is scoped to its own grants.

---

**How do I migrate from Oxigraph to PostgreSQL?**

```bash
aevum store migrate --from oxigraph:/path --to postgres:postgresql://...
```

This migrates the knowledge graph, consent ledger, and episodic ledger.

---

**What is a "complication"?**

Aevum's word for a policy-governed extension. Not a plugin, not a module —
a complication. Each complication goes through a 7-state lifecycle
(DISCOVERED → PENDING → APPROVED → ACTIVE → SUSPENDED → DEPRECATED → REMOVED)
and is logged to the episodic ledger at every state transition.
