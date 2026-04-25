"""ConsentLedgerProtocol — runtime-checkable interface for consent ledger backends."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from aevum.core.consent.models import ConsentGrant


@runtime_checkable
class ConsentLedgerProtocol(Protocol):
    def add_grant(self, grant: ConsentGrant) -> None: ...
    def revoke_grant(self, grant_id: str) -> None: ...
    def has_consent(
        self,
        *,
        subject_id: str,
        operation: str,
        grantee_id: str,
        purpose: str | None = None,
    ) -> bool: ...
    def all_grants(self) -> list[ConsentGrant]: ...
