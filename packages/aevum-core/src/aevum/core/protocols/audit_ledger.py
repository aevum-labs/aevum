"""
AuditLedgerProtocol -- runtime-checkable Protocol for episodic ledger backends.

InMemoryLedger (dev) and PostgresLedger (production) both satisfy this Protocol.
Engine accepts a ledger= kwarg following the same pattern as graph_store= and consent_ledger=.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from aevum.core.audit.event import AuditEvent


@runtime_checkable
class AuditLedgerProtocol(Protocol):
    def append(
        self,
        *,
        event_type: str,
        payload: dict[str, Any],
        actor: str,
        episode_id: str | None = None,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> AuditEvent: ...

    def get(self, audit_id: str) -> AuditEvent: ...
    def all_events(self) -> list[AuditEvent]: ...
    def count(self) -> int: ...

    def last_audit_id(self) -> str | None:
        """
        Return the audit_id of the most recently appended event,
        or None if the ledger is empty.

        Used by Engine._write_session_start() to set causation_id on the
        new session's session.start event, creating an explicit cross-session
        chain link for persistent backends. In-memory backends always return None.
        """
        ...

    def __delitem__(self, key: object) -> None: ...
    def __setitem__(self, key: object, value: object) -> None: ...
