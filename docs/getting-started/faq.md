# FAQ

**Does Aevum send any data outside my environment?**

No. Nothing leaves your process. If you configure an optional OPA
sidecar, it runs in your own infrastructure.

---

**Do I need a database to use Aevum?**

No. The default `Engine()` uses in-memory storage. Data does not
persist across restarts in this mode. For persistence, add
`aevum-store-oxigraph` (embedded, no database service required) or
`aevum-store-postgres`.

---

**Is in-memory mode suitable for production?**

No. In-memory storage means the sigchain and all data are lost on
process restart. Use `aevum-store-oxigraph` or `aevum-store-postgres`
for any persistent workload.

---

**What happens if I don't have cedarpy installed?**

The kernel warns at startup and falls back to permissive consent
decisions. The five unconditional barriers still fire unconditionally —
crisis detection, classification ceiling, consent (fast-path denials),
audit immutability, and provenance are not affected by whether Cedar
is installed.

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

**What is the difference between `replay` and `query`?**

`query` retrieves current data from the knowledge graph
(`urn:aevum:knowledge`).

`replay` retrieves and cryptographically verifies the signed record of
a past operation from the provenance ledger (`urn:aevum:provenance`).
It does not re-execute the agent's reasoning, re-call the LLM, or
reconstruct the full graph state at a past moment — it returns the
exact signed record of what was recorded at the time of the original
operation.

See [The Five Functions](../concepts/five-functions.md) for the full
distinction.

---

**How do I handle GDPR right-to-erasure?**

Call `engine.revoke_consent_grant(grant_id)`. The data in the knowledge
graph becomes immediately unreachable at the next operation. Physical
deletion from the storage backend is a separate step if required by
your data retention policy.

Note: Aevum's append-only ledger retains signed audit records of past
operations. Depending on your jurisdiction and the nature of the data,
you may need to assess how this interacts with your erasure obligations.
This is a legal question for qualified counsel, not a configuration
question.

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

**Can multiple agents share the same Engine instance?**

Yes, with different `grantee_id` values in their consent grants.
Each agent's access is scoped to its own grants.

---

**How do I migrate from Oxigraph to PostgreSQL?**

```bash
aevum store migrate --from oxigraph:<path> --to postgres:<dsn>
```

This migrates the knowledge graph, consent ledger, and episodic ledger.

---

**What is a "complication"?**

Aevum's term for a policy-governed extension. Not a plugin, not a
module — a complication.

---

**Does Aevum make my application compliant with GDPR, HIPAA,
the EU AI Act, or other regulations?**

No. Aevum provides technical controls — tamper-evident audit records,
consent documentation, and human-review gates — designed to support
compliance programs. Whether those controls satisfy a specific
regulatory obligation depends on your deployment, configuration,
jurisdiction, and the broader controls in your application. Aevum is
not certified to any regulatory standard, and using Aevum does not
constitute compliance with any law or regulation. Consult qualified
legal counsel for compliance decisions.

---

**Does Aevum integrate with my identity provider?**

Aevum's consent grants use `grantee_id` to identify which actor is
making a request. Your application validates the token from your
identity provider using any standard JWT library, extracts the relevant
claim (typically `sub` or a custom claim), and passes it as `actor`
when calling the kernel. No Aevum-specific auth package is required.
