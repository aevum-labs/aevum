---
title: "Capture Faithfulness vs. Tamper-Evidence in AI Agent Logs"
description: "Tamper-evidence proves a record was not altered after it was written. It does not prove every agent action was captured in the first place. This page explains the boundary and how Aevum's capture.gap mechanism makes it visible."
---

# Capture Faithfulness Is a Property of the Integration, Not the Record

Aevum proves the integrity, ordering, authenticity, and time of records *after
they are written* — that what was recorded has not been altered. It does not,
by itself, guarantee that every action an agent took was captured, or that a
recorded action faithfully reflects what happened at the boundary where Aevum
observes it. Aevum records the capture surface and emits explicit
`capture.gap` events when it detects a gap, but completeness-at-capture
depends on the integration's coverage.

**Tamper-evidence is a property of the record; faithfulness-at-capture is a
property of the integration.**

## Two different guarantees

[Tamper-evident logging](tamper-evident-logs.md) answers: *given an entry in
the sigchain, can I trust that it hasn't been altered?* `verify_sigchain()`
answers this with a hash-chain walk from genesis — yes or no, deterministically.

Capture faithfulness answers a different question: *did everything that
happened get turned into an entry in the first place?* No hash chain can
answer this, because a missing entry leaves no broken link to detect — it
leaves nothing at all. The only way an auditor learns about a gap is if the
integration says so.

## How Aevum makes gaps visible

`engine.record_capture_gap()` writes a `capture.gap` `AuditEvent` declaring
that an out-of-band call (LLM, tool, MCP) happened outside the governed path.
`capture_surface` reports which integrations are wired up (e.g.
`{"llm": true, "mcp": false}`) so a deployer can see, at a glance, which
surfaces are instrumented and which are not.

This turns an invisible gap into an auditable one: an auditor reviewing the
sigchain sees a `capture.gap` event and knows "the operator declared an
out-of-band call was made here," rather than seeing nothing and assuming
nothing happened.

## What this does not solve

The gap event is written *after* the out-of-band call, not before — if the
process crashes between the call and the `record_capture_gap()` invocation,
no gap event is written and the call is invisible to the sigchain. See
[THREAT_MODEL.md — record_capture_gap() Ordering Limitation (D-03)](https://github.com/aevum-labs/aevum/blob/main/THREAT_MODEL.md)
for the full failure mode and mitigation.

Capture faithfulness also cannot be retrofitted by Aevum itself: it depends
entirely on every consequential call site in your integration calling a
governed function or `record_capture_gap()`. Aevum gives you the mechanism
to declare gaps; it cannot detect a gap that was never declared.

## See also

- [Tamper-Evident Logging](tamper-evident-logs.md)
- [THREAT_MODEL.md](https://github.com/aevum-labs/aevum/blob/main/THREAT_MODEL.md) — Trust Assumptions
- [Audit Events reference](../reference/api.md#auditevent)
