---
description: "Financial services: how Aevum's tamper-evident, independently verifiable audit trail supports SEC Rule 17a-4 and FINRA Rule 4511 recordkeeping for AI agents in broker-dealer environments."
---

# Financial Services — Audit-Defensible Records for AI Agents

AI agents in financial services increasingly take or inform actions that become
regulated records: order submission and routing, the rationale behind a trade,
suitability assessments, and customer communications. When an examiner later
asks a firm to produce *and authenticate* those records, ordinary application
logs and observability traces fall short — they are mutable and self-attested.
Aevum produces the evidence layer that this setting actually requires.

> **This page is not legal advice.** Whether and how SEC Rule 17a-4, FINRA Rule
> 4511, or any other obligation applies to your systems is a determination for
> your compliance and legal counsel. Aevum provides a technical control; it does
> not make a firm compliant on its own.

## The recordkeeping standard

**SEC Rule 17a-4** governs how broker-dealers preserve electronic records. Since
the 2022 amendments (compliance date May 2023), firms may preserve records using
**either**:

- a **write-once, read-many (WORM)** system, **or**
- an **audit-trail alternative** — a system that maintains a complete,
  time-stamped audit trail that permits the recreation of an original record if
  it is later altered or deleted, with the authenticity and accuracy of the
  records verifiable.

**FINRA Rule 4511** incorporates these recordkeeping and retention obligations
for FINRA members. Note that AI-generated content can itself become a record
when it is communicated (for example, an agent-drafted client message).

## How Aevum maps to the audit-trail alternative

| What the audit-trail alternative expects | Aevum mechanism |
|---|---|
| Recreate an original record after it is altered or deleted | Append-only sigchain — every entry is chained to its predecessor; nothing is overwritten in place, so prior states are reconstructable |
| Verifiable **authenticity** | Each entry is Ed25519-signed; any party can verify the signature with the public key alone |
| Verifiable **accuracy / integrity** | SHA3-256 hash chain — altering any past entry breaks the chain and fails verification |
| **Time-stamped** audit trail | Each receipt carries an RFC 3161 trusted timestamp; receipts can be anchored to a public transparency log (Rekor v2) |
| Independent / examiner access | Receipts are portable (COSE_Sign1) and verifiable by a third party with no access to the firm's systems |

## What Aevum is — and is not — here

- **Is:** the cryptographic evidence layer that makes an AI agent's actions
  tamper-evident, independently verifiable, and reconstructable after the fact.
- **Is not:** a designated-third-party (D3P) service, a WORM storage product, or
  a substitute for your retention infrastructure and recordkeeping policies.
  Aevum produces the verifiable records; where and how you retain them, and your
  D3P/notification arrangements, remain yours.

## Example

A worked code example (classification levels, a signed `trading.order.submitted`
event, and a human-review gate for large trades) is in the
[Finance domain example](../domain-examples/finance.md).

## Next steps

- [Tamper-evident logs](../concepts/tamper-evident-logs.md) — how the sigchain and receipts work
- [EU AI Act Article 12](article12.md) — logging obligations for high-risk systems
- [Quickstart](../getting-started/quickstart/) — first signed, chained record in minutes
