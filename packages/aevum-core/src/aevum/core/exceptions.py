"""Aevum exception hierarchy."""

from __future__ import annotations


class AevumError(Exception):
    """Base class for all Aevum exceptions."""


class BarrierViolationError(AevumError):
    """A hardcoded absolute barrier was violated."""


class ConsentRequiredError(AevumError):
    """Consent grant required but not found."""


class ProvenanceRequiredError(AevumError):
    """Provenance record required but missing or invalid."""


class PolicyDeniedError(AevumError):
    """Policy engine denied the operation."""


class ReplayNotFoundError(AevumError):
    """No ledger entry found for the given audit_id."""


class ReviewNotFoundError(AevumError):
    """No pending review found for the given audit_id."""


class ReviewAlreadyResolvedError(AevumError):
    """The review has already been approved or vetoed."""


class ComplicationError(AevumError):
    """A complication failed during execution."""


class GraphStoreError(AevumError):
    """The graph store operation failed."""


class SignatureError(AevumError):
    """Ed25519 signature verification failed."""


class ConfigurationError(AevumError):
    """Invalid or missing configuration."""
