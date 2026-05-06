# Aevum Event Schema v1

The machine-readable JSON Schema is at
[`spec/aevum-event-v1.json`](aevum-event-v1.json).

The schema defines the structure of every AuditEvent as returned by
`Engine.get_ledger_entries()`. See the
[Signing Specification](aevum-signing-v1.md) for verification procedures.

## Field summary

See the JSON Schema for full constraints. Key fields:

| Field | Type | Description |
|-------|------|-------------|
| event_id | string | UUID v7 (globally unique, time-ordered) |
| episode_id | string | Groups events into a logical workflow episode |
| sequence | integer | Chain position (1-based); always 1 for session.start |
| event_type | string | Dotted namespace (e.g. `session.start`, `ingest.accepted`) |
| actor | string | Who caused this event (e.g. `aevum-core`, `agent`) |
| system_time | integer | HLC nanoseconds — use for causal ordering |
| valid_from | string | Wall-clock ISO 8601 timestamp |
| valid_to | string\|null | Validity end timestamp; null for point-in-time events |
| causation_id | string\|null | audit_id of the causing event |
| correlation_id | string\|null | Deployment-wide correlation token |
| trace_id | string\|null | OTel W3C trace ID |
| span_id | string\|null | OTel W3C span ID |
| prior_hash | string | SHA3-256 of previous event's signing fields |
| payload_hash | string | SHA3-256 of payload (JCS-canonical) |
| signature | string | Ed25519 over SHA3-256(signing fields), base64url |
| signer_key_id | string | Signing key identifier |
| schema_version | string | Always `"1.0"` |
| payload | object | Event-specific structured data |
| audit_id | string | `urn:aevum:audit:{event_id}` |

## Event types

| event_type | Description |
|------------|-------------|
| `session.start` | Kernel startup; always sequence 1 |
| `ingest.accepted` | Data ingested through the governed membrane |
| `ingest.rejected` | Ingest denied by policy or consent |
| `query.accepted` | Graph traversal executed |
| `review.created` | Review checkpoint created |
| `commit.accepted` | Manual commit appended |
| `replay.started` | Replay of a past decision begun |
| `capture.gap` | Out-of-band capture surface call declared |

## session.start payload

```json
{
  "capture_surface": {
    "llm": false,
    "mcp": false
  },
  "key_provenance": "in-process"
}
```

`key_provenance` values: `in-process`, `external`, `vault-transit`, `aws-kms`, `pkcs11`.

## capture.gap payload

```json
{
  "gap_type": "llm",
  "reason": "direct_api_call",
  "model_hint": "claude-opus-4-7"
}
```

`gap_type` values: `llm`, `mcp`, `tool`, `custom`.
`reason` and `gap_type` are required; `model_hint` is optional.
