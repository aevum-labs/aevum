---
description: "The MCP specification has no audit logging requirement. The aevum-mcp package adds tamper-evident, sigchain-anchored tool-call provenance to any MCP-compatible host."
---

# MCP Audit Trails with aevum-mcp

The Model Context Protocol specification (as of 2026-06) defines no requirement for audit logging of tool calls. There is no protocol-level mechanism for an MCP client to verify what a server executed, in what order, or whether the record has been altered. This guide shows how `aevum-mcp` adds tamper-evident provenance to MCP tool calls.

## What the MCP spec does and does not provide

MCP defines the wire protocol for tool discovery, invocation, and result return. The June 2025 revision added mandatory OAuth 2.1 + PKCE authentication — a significant improvement for access control. What remains absent from the spec: audit logging format, tamper-evident storage, session reconstruction, and any client-verifiable record of what the server executed. The Cloud Security Alliance's [modelcontextprotocol-security.io](https://modelcontextprotocol-security.io) initiative is the ongoing community effort to address these gaps at the protocol level. Christian Posta's analysis ("The MCP Authorization Spec Is... a Mess for Enterprise") documents the enterprise authentication complexity that arises from the current spec's approach — the audit gap is a separate but related concern that `aevum-mcp` addresses at the application layer.

## What aevum-mcp adds

The `aevum-mcp` package is an Aevum complication that surfaces Aevum's five functions as MCP tools. Every tool invocation is recorded as a sigchain entry in the episodic ledger before the result is returned.

What this means practically:

- Every tool call has an `audit_id` in the episodic ledger
- The `audit_id` can be replayed to reconstruct the exact input and output
- The sigchain covers the full session — tampering with any entry breaks the hash chain and is detected by `verify_sigchain()`
- Access to replay past tool calls requires an explicit consent grant with `"replay"` in operations — audit access is separated from operational access

## Setup

```python
"""
aevum-mcp setup — governed MCP tool invocation with sigchain audit.

Install: pip install aevum-core aevum-mcp
"""
from aevum.core import Engine
from aevum.core.consent.models import ConsentGrant

# Initialise the kernel
engine = Engine()

# Grant the MCP agent operational access
engine.add_consent_grant(ConsentGrant(
    grant_id="mcp-agent-grant-001",
    subject_id="user-session-abc123",
    grantee_id="mcp-agent",
    operations=["ingest", "query"],
    purpose="user-assistance",
    classification_max=1,
    granted_at="2026-01-01T00:00:00Z",
    expires_at="2030-01-01T00:00:00Z",
))

# Grant a separate audit identity replay-only access
engine.add_consent_grant(ConsentGrant(
    grant_id="mcp-audit-grant-001",
    subject_id="user-session-abc123",
    grantee_id="security-auditor",
    operations=["replay"],
    purpose="security-audit",
    classification_max=1,
    granted_at="2026-01-01T00:00:00Z",
    expires_at="2030-01-01T00:00:00Z",
))

# Record a tool invocation via ingest
# In practice, aevum-mcp does this automatically for each MCP tool call
tool_call_result = engine.ingest(
    data={
        "tool": "read_file",
        "arguments": {"path": "/workspace/report.md"},
        "result_summary": "File read successfully, 2,847 bytes",
    },
    provenance={
        "source_id": "mcp-host",
        "chain_of_custody": ["mcp-client", "mcp-host", "mcp-agent"],
        "classification": 1,
        "model_id": "claude-sonnet-4-6",
    },
    purpose="user-assistance",
    subject_id="user-session-abc123",
    actor="mcp-agent",
    idempotency_key="tool-call-uuid-xyz",
)

audit_id = tool_call_result.audit_id
print(f"Tool call recorded: {audit_id}")

# Later — security audit replays the exact tool call
replay_result = engine.replay(
    audit_id=audit_id,
    actor="security-auditor",
)

print(replay_result.data["replayed_payload"]["tool"])         # read_file
print(replay_result.data["replayed_payload"]["arguments"])    # {"path": "/workspace/report.md"}
print(replay_result.data["event_metadata"]["actor"])          # mcp-agent

# Verify the full session sigchain
print(engine.verify_sigchain())  # True
```

## Separating operational and audit access

The grant separation above is intentional and load-bearing. The `mcp-agent` cannot call `replay` — its grant covers only `ingest` and `query`. The `security-auditor` cannot ingest new data — its grant covers only `replay`. This separation ensures that audit access does not confer write access and operational access does not confer the ability to modify the audit record. An attacker who compromises the `mcp-agent` identity gains the ability to ingest data and query the knowledge graph, but cannot replay past sessions or read the raw audit trail. An auditor with `security-auditor` access can reconstruct any past tool invocation but cannot write to the knowledge graph.

## What this does not cover

Aevum records what the agent ingested and queried. It does not intercept raw MCP wire traffic — the MCP host must call the Aevum engine for each tool invocation. For a fully instrumented MCP deployment, the `aevum-mcp` complication handles this integration automatically; the aevum-mcp package documentation covers installation and configuration of the automatic instrumentation.

## See also

- [The Sigchain](../concepts/sigchain.md)
- [Replay vs. Observability](../concepts/replay-vs-observability.md)
- [Getting Started — MCP Setup](../getting-started/mcp-setup.md)
