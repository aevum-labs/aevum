---
description: "ConsentGrant reference: the permission unit for ingest, query, replay, and export operations — fields, validation rules, and OR-Set revocation."
---

# ConsentGrant

The unit of permission. Every `ingest`, `query`, and `replay` operation
requires an active, non-expired `ConsentGrant` for the subject and operation.

Valid operations: `"ingest"`, `"query"`, `"replay"`, `"export"`

::: aevum.core.consent.models.ConsentGrant
