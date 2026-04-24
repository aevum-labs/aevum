"""
Engine — the public entry point wiring all kernel components.
Usage: from aevum.core import Engine; engine = Engine()
"""

from __future__ import annotations

from typing import Any

from aevum.core.audit.ledger import InMemoryLedger
from aevum.core.audit.sigchain import Sigchain
from aevum.core.consent.ledger import ConsentLedger
from aevum.core.consent.models import ConsentGrant
from aevum.core.envelope.models import OutputEnvelope
from aevum.core.functions.commit import commit as _commit
from aevum.core.functions.ingest import ingest as _ingest
from aevum.core.functions.query import query as _query
from aevum.core.functions.replay import replay as _replay
from aevum.core.functions.review import ReviewStore
from aevum.core.functions.review import review as _review
from aevum.core.graph.memory import InMemoryGraphStore
from aevum.core.policy.bridge import PolicyBridge
from aevum.core.protocols.graph_store import GraphStore


class Engine:
    """
    The Aevum context kernel.

    Engine() — development defaults (in-memory everything).
    Engine(graph_store=OxigraphStore(), opa_url="http://opa:8181") — production.
    """

    def __init__(
        self,
        *,
        graph_store: GraphStore | None = None,
        opa_url: str | None = None,
        sigchain: Sigchain | None = None,
    ) -> None:
        self._sigchain: Sigchain = sigchain or Sigchain()
        self._ledger: InMemoryLedger = InMemoryLedger(self._sigchain)
        self._consent_ledger: ConsentLedger = ConsentLedger()
        self._graph: GraphStore = graph_store or InMemoryGraphStore()
        self._policy: PolicyBridge = PolicyBridge(opa_url=opa_url)
        self._review_store: ReviewStore = ReviewStore()
        self._idempotency_cache: dict[str, OutputEnvelope] = {}

    def add_consent_grant(self, grant: ConsentGrant) -> None:
        self._consent_ledger.add_grant(grant)

    def revoke_consent_grant(self, grant_id: str) -> None:
        self._consent_ledger.revoke_grant(grant_id)

    def ingest(self, *, data: dict[str, Any], provenance: dict[str, Any],
               purpose: str, subject_id: str, actor: str,
               idempotency_key: str | None = None,
               episode_id: str | None = None, correlation_id: str | None = None) -> OutputEnvelope:
        return _ingest(data=data, provenance=provenance, purpose=purpose, subject_id=subject_id,
                       actor=actor, ledger=self._ledger, consent_ledger=self._consent_ledger,
                       graph=self._graph, idempotency_key=idempotency_key,
                       idempotency_cache=self._idempotency_cache,
                       episode_id=episode_id, correlation_id=correlation_id)

    def query(self, *, purpose: str, subject_ids: list[str], actor: str,
              constraints: dict[str, Any] | None = None, classification_max: int = 0,
              episode_id: str | None = None, correlation_id: str | None = None) -> OutputEnvelope:
        return _query(purpose=purpose, subject_ids=subject_ids, actor=actor,
                      ledger=self._ledger, consent_ledger=self._consent_ledger,
                      graph=self._graph, constraints=constraints,
                      classification_max=classification_max,
                      episode_id=episode_id, correlation_id=correlation_id)

    def review(self, *, audit_id: str, actor: str, action: str | None = None,
               episode_id: str | None = None, correlation_id: str | None = None) -> OutputEnvelope:
        return _review(audit_id=audit_id, action=action, actor=actor,
                       ledger=self._ledger, review_store=self._review_store,
                       episode_id=episode_id, correlation_id=correlation_id)

    def commit(self, *, event_type: str, payload: dict[str, Any], actor: str,
               idempotency_key: str | None = None,
               episode_id: str | None = None, correlation_id: str | None = None) -> OutputEnvelope:
        return _commit(event_type=event_type, payload=payload, actor=actor,
                       ledger=self._ledger, idempotency_key=idempotency_key,
                       idempotency_cache=self._idempotency_cache,
                       episode_id=episode_id, correlation_id=correlation_id)

    def replay(self, *, audit_id: str, actor: str, scope: list[str] | None = None,
               episode_id: str | None = None, correlation_id: str | None = None) -> OutputEnvelope:
        return _replay(audit_id=audit_id, actor=actor, ledger=self._ledger,
                       consent_ledger=self._consent_ledger, scope=scope,
                       episode_id=episode_id, correlation_id=correlation_id)

    def create_review(self, *, proposed_action: str, reason: str, actor: str,
                      autonomy_level: int = 1, risk_assessment: str = "",
                      deadline_iso: str | None = None) -> str:
        return self._review_store.create(proposed_action=proposed_action, reason=reason,
                                         actor=actor, autonomy_level=autonomy_level,
                                         risk_assessment=risk_assessment, deadline_iso=deadline_iso)

    def get_ledger_entries(self) -> list[dict[str, Any]]:
        """Conformance hook — not part of public API."""
        return [{"audit_id": e.audit_id(), "event_type": e.event_type,
                 "actor": e.actor, "payload": e.payload, "sequence": e.sequence}
                for e in self._ledger.all_events()]

    def ledger_count(self) -> int:
        return self._ledger.count()

    def verify_sigchain(self) -> bool:
        return self._sigchain.verify_chain(self._ledger.all_events())
