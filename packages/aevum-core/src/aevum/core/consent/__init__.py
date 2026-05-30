# SPDX-License-Identifier: Apache-2.0
"""aevum.core.consent — OR-Set CRDT consent ledger and grant lifecycle models.

Consent is a legal precondition for any data operation in Aevum (GDPR Art. 6). No graph
traversal or data write may proceed without an active consent grant for the requesting
principal, subject, and operation triple. This package provides the data model (ConsentGrant)
and the ledger that tracks grants and revocations.

OR-Set CRDT semantics (Shapiro et al. 2011, "Conflict-free Replicated Data Types"):
  Grant:  add the grant ID to the add-set (INSERT INTO consent_grants)
  Revoke: add the same ID to the remove-set (INSERT INTO consent_revocations)
  Check:  ID is in the add-set AND NOT in the remove-set AND not expired
  In Aevum's single-node deployment, revoke is always immediate (no concurrent ops).
  The OR-Set structure is preserved for future distributed-ledger compatibility.

GDPR alignment:
  Art. 6  — Lawful basis: each ConsentGrant record documents the basis for processing.
  Art. 7  — Conditions: grants are purpose-specific, identity-bound, and time-limited.
  Art. 17 — Right to erasure: ConsentLedger.shred() destroys the subject's AES-256-GCM
             data-encryption key (DEK), making all encrypted data permanently unreadable.
             The grant audit record itself remains (I1-APPEND_ONLY — erasure is provable
             precisely because the chain entry showing "DEK destroyed" is immutable).
"""

from aevum.core.consent.ledger import ConsentLedger, ConsentRequired
from aevum.core.consent.models import ConsentGrant

__all__ = ["ConsentLedger", "ConsentGrant", "ConsentRequired"]
