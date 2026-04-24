"""
ConformanceAdapter — wraps Engine to satisfy AevumProtocol (Phase 2 interface).
Engine returns Pydantic models; this adapter returns dicts for the conformance suite.
"""

from __future__ import annotations

from typing import Any

from aevum.core.consent.models import ConsentGrant
from aevum.core.engine import Engine


class ConformanceAdapter:
    def __init__(self, engine: Engine | None = None) -> None:
        self._engine = engine or Engine()

    def add_consent_grant(self, grant: dict[str, Any]) -> None:
        self._engine.add_consent_grant(ConsentGrant(**grant))

    def ingest(self, data: dict[str, Any], provenance: dict[str, Any],
               purpose: str, subject_id: str,
               idempotency_key: str | None = None) -> dict[str, Any]:
        return self._engine.ingest(data=data, provenance=provenance, purpose=purpose,
                                   subject_id=subject_id, actor="conformance-test",
                                   idempotency_key=idempotency_key).model_dump()

    def query(self, purpose: str, subject_ids: list[str],
              constraints: dict[str, Any] | None = None,
              classification_max: int = 0) -> dict[str, Any]:
        return self._engine.query(purpose=purpose, subject_ids=subject_ids,
                                  actor="conformance-test", constraints=constraints,
                                  classification_max=classification_max).model_dump()

    def review(self, audit_id: str, action: str | None = None) -> dict[str, Any]:
        return self._engine.review(audit_id=audit_id, actor="conformance-test",
                                   action=action).model_dump()

    def commit(self, event_type: str, payload: dict[str, Any],
               idempotency_key: str | None = None) -> dict[str, Any]:
        return self._engine.commit(event_type=event_type, payload=payload,
                                   actor="conformance-test",
                                   idempotency_key=idempotency_key).model_dump()

    def replay(self, audit_id: str, scope: list[str] | None = None) -> dict[str, Any]:
        return self._engine.replay(audit_id=audit_id, actor="conformance-test",
                                   scope=scope).model_dump()

    def get_ledger_entries(self) -> list[dict[str, Any]]:
        return self._engine.get_ledger_entries()
