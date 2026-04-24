"""
Consent ledger — OR-Set semantics. Spec Section 07.
Phase 3: in-memory. Cedar integration arrives Phase 6.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime

from aevum.core.consent.models import ConsentGrant


class ConsentLedger:
    """Thread-safe in-memory consent ledger. Revocation wins over concurrent grants."""

    def __init__(self) -> None:
        self._grants: dict[str, ConsentGrant] = {}
        self._lock = threading.Lock()

    def add_grant(self, grant: ConsentGrant) -> None:
        with self._lock:
            self._grants[grant.grant_id] = grant

    def revoke_grant(self, grant_id: str) -> None:
        with self._lock:
            if grant_id in self._grants:
                g = self._grants[grant_id]
                self._grants[grant_id] = ConsentGrant(
                    **{**g.model_dump(), "revocation_status": "revoked"}
                )

    def has_consent(
        self,
        *,
        subject_id: str,
        operation: str,
        grantee_id: str,
        purpose: str | None = None,
    ) -> bool:
        now = datetime.now(UTC)
        with self._lock:
            for grant in self._grants.values():
                if grant.subject_id != subject_id:
                    continue
                if grant.grantee_id != grantee_id:
                    continue
                if operation not in grant.operations:
                    continue
                if grant.revocation_status != "active":
                    continue
                try:
                    expires = datetime.fromisoformat(grant.expires_at.replace("Z", "+00:00"))
                    if now > expires:
                        continue
                except ValueError:
                    continue
                return True
        return False

    def all_grants(self) -> list[ConsentGrant]:
        with self._lock:
            return list(self._grants.values())
