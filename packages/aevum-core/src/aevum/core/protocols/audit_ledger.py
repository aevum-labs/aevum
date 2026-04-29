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
    def __delitem__(self, key: object) -> None: ...
    def __setitem__(self, key: object, value: object) -> None: ...
