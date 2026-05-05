---
description: "Domain pattern index: how Aevum's classification levels map to HIPAA, SOX, and GDPR, with examples for healthcare, finance, and legal industries."
---

# Domain Examples

These examples show how Aevum's consent and classification primitives
apply to regulated industries. They use `aevum-core` directly — no
additional packages are required.

Domain packs (pre-built configurations for each industry) are planned
for a future release.

## Available examples

| Domain | Standard | Key concern |
|---|---|---|
| [Healthcare (FHIR R4)](healthcare.md) | HIPAA | PHI classification, TPO consent |
| [Finance (SOX)](finance.md) | SOX / FIBO | Financial data classification, audit trail |
| [Legal (GDPR)](legal.md) | GDPR | Purpose limitation, right to erasure |

## The pattern

Each domain example follows the same structure:

1. **Classification mapping** — how the domain's data categories map to Aevum's
   four classification levels (0=public, 1=internal, 2=identified, 3=sensitive)

2. **Consent grant setup** — how to configure grants that satisfy the domain's
   consent requirements

3. **Ingest example** — ingesting a domain-specific data format with appropriate
   provenance and classification

4. **Query example** — querying with purpose and classification ceiling

5. **Review example** — using the review gate for domain-specific approval workflows

## Classification levels

Aevum uses four classification levels that map across all domains:

| Level | General | Healthcare | Finance | Legal |
|---|---|---|---|---|
| 0 | Public | De-identified | Public filings | Public records |
| 1 | Internal | Limited dataset | Internal only | Restricted |
| 2 | Confidential | Identified PHI | Non-public financial | Personal data |
| 3 | Highly sensitive | Sensitive PHI | Material non-public | Special category |

## Enterprise scenarios

For cross-industry patterns (loan underwriting, claims processing, document review),
see the [Architecture](/learn/architecture/) page.
