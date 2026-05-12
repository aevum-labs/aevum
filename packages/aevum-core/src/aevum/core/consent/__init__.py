"""aevum.core.consent — Consent ledger and grant models."""

from aevum.core.consent.ledger import ConsentLedger
from aevum.core.consent.models import ConsentGrant


class ConsentRequired(Exception):
    """
    Raised when an operation requires consent that has not been granted.
    This is an absolute barrier — the operation is blocked entirely.

    Phase 1 stub. Full OR-Set CRDT implementation with crypto-shredding in Phase 3.
    """


__all__ = ["ConsentLedger", "ConsentGrant", "ConsentRequired"]
