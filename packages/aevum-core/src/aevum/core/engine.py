"""
Engine — wires all kernel components together.
"""

from __future__ import annotations

from typing import Any

from aevum.core.audit.event import AuditEvent
from aevum.core.audit.ledger import InMemoryLedger
from aevum.core.audit.sigchain import Sigchain
from aevum.core.complications import (
    CircuitBreaker,
    ComplicationRegistry,
    ComplicationState,
    ConflictDetector,
    ManifestValidator,
    WebhookRegistry,
)
from aevum.core.consent.ledger import ConsentLedger
from aevum.core.consent.models import ConsentGrant
from aevum.core.envelope.models import OutputEnvelope
from aevum.core.exceptions import ComplicationError
from aevum.core.functions.commit import commit as _commit
from aevum.core.functions.ingest import ingest as _ingest
from aevum.core.functions.query import query as _query
from aevum.core.functions.replay import replay as _replay
from aevum.core.functions.review import ReviewStore
from aevum.core.functions.review import review as _review
from aevum.core.graph.memory import InMemoryGraphStore
from aevum.core.policy.bridge import PolicyBridge
from aevum.core.protocols.audit_ledger import AuditLedgerProtocol
from aevum.core.protocols.consent_ledger import ConsentLedgerProtocol
from aevum.core.protocols.graph_store import GraphStore

# Check for AgentComplication dynamically to avoid circular import
# (aevum-sdk is not a dependency of aevum-core)


class Engine:
    """
    The Aevum context kernel.

    Wires together the episodic ledger, consent ledger, graph store,
    policy bridge, complication registry, and the five governed functions.
    """

    def __init__(
        self,
        *,
        graph_store: GraphStore | None = None,
        opa_url: str | None = None,
        sigchain: Sigchain | None = None,
        consent_ledger: ConsentLedgerProtocol | None = None,
        ledger: AuditLedgerProtocol | None = None,
    ) -> None:
        self._sigchain = sigchain or Sigchain()
        self._ledger = ledger or InMemoryLedger(self._sigchain)
        self._consent_ledger: ConsentLedgerProtocol = consent_ledger or ConsentLedger()
        self._graph: GraphStore = graph_store or InMemoryGraphStore()
        self._policy = PolicyBridge(opa_url=opa_url)
        self._review_store = ReviewStore()
        self._idempotency_cache: dict[str, OutputEnvelope] = {}

        self._complication_registry = ComplicationRegistry()
        self._circuit_breakers: dict[str, CircuitBreaker] = {}
        self._manifest_validator = ManifestValidator()
        self._conflict_detector = ConflictDetector()
        self._webhook_registry = WebhookRegistry(ledger=self._ledger)

        self._write_session_start()

    def _write_session_start(self) -> None:
        registered = self._complication_registry.all_entries()
        llm_active = any("llm" in name.lower() for name in registered)
        mcp_active = any("mcp" in name.lower() for name in registered)
        self._ledger.append(
            event_type="session.start",
            payload={
                "capture_surface": {"llm": llm_active, "mcp": mcp_active},
                "key_provenance": self._sigchain.key_provenance,
            },
            actor="aevum-core",
        )

    # ── Consent management ────────────────────────────────────────────────────

    def add_consent_grant(self, grant: ConsentGrant) -> None:
        self._consent_ledger.add_grant(grant)

    def revoke_consent_grant(self, grant_id: str) -> None:
        self._consent_ledger.revoke_grant(grant_id)

    # ── Complication management ───────────────────────────────────────────────

    def install_complication(self, instance: Any, *, auto_approve: bool = False) -> None:
        """
        Install a complication: validate manifest, check conflicts, register.

        Args:
            instance: A Complication instance (from aevum.sdk).
            auto_approve: If True, immediately approve (for testing / trusted installs).

        Raises:
            ComplicationError: if manifest is invalid or capability conflicts exist.
        """
        manifest = instance.manifest()
        name = manifest.get("name", "")

        # Validate manifest schema (Ed25519 optional)
        errors = self._manifest_validator.validate(manifest)
        if errors:
            raise ComplicationError(
                f"Complication '{name}' manifest validation failed: {errors}"
            )

        # Check capability conflicts against active complications
        active_manifests = [
            c.manifest() for c in self._complication_registry.active_complications()
        ]
        conflicts = self._conflict_detector.check(manifest, active_manifests)
        if conflicts:
            raise ComplicationError(
                f"Complication '{name}' has capability conflicts: {conflicts}"
            )

        # Register in DISCOVERED state
        self._complication_registry.install(manifest, instance)

        # Technical validation: DISCOVERED → PENDING
        self._complication_registry.validate(name)

        # Initialise circuit breaker
        self._circuit_breakers[name] = CircuitBreaker()

        # Inject review callback for AgentComplication autonomy enforcement
        if hasattr(instance, "set_review_callback"):
            instance.set_review_callback(self.create_review)

        # Log to ledger
        self._ledger.append(
            event_type="complication.installed",
            payload={"name": name, "version": manifest.get("version", "")},
            actor="aevum-core",
        )

        if auto_approve:
            self.approve_complication(name)

    def approve_complication(self, name: str) -> None:
        """Admin approval: PENDING → APPROVED → ACTIVE."""
        self._complication_registry.approve(name)
        self._ledger.append(
            event_type="complication.approved",
            payload={"name": name},
            actor="aevum-core",
        )

    def suspend_complication(self, name: str) -> None:
        """Admin suspension: ACTIVE → SUSPENDED."""
        self._complication_registry.suspend(name)
        self._ledger.append(
            event_type="complication.suspended",
            payload={"name": name},
            actor="aevum-core",
        )

    def resume_complication(self, name: str) -> None:
        """Admin resume: SUSPENDED → ACTIVE."""
        self._complication_registry.resume(name)

    def complication_state(self, name: str) -> ComplicationState:
        return self._complication_registry.state(name)

    def list_complications(self) -> dict[str, dict[str, Any]]:
        return self._complication_registry.all_entries()

    # ── Webhook management ────────────────────────────────────────────────────

    def register_webhook(
        self,
        webhook_id: str,
        url: str,
        secret: str,
        events: list[str] | None = None,
    ) -> None:
        self._webhook_registry.register(webhook_id, url, secret, events)

    def deregister_webhook(self, webhook_id: str) -> None:
        self._webhook_registry.deregister(webhook_id)

    def reset_agent_actions(self, complication_name: str) -> None:
        """
        Reset the consecutive action counter for an AgentComplication.
        Call this after a review is resolved (approved or vetoed).
        """
        complication = self._get_active_complication(complication_name)
        if complication is not None and hasattr(complication, "reset_consecutive_actions"):
            complication.reset_consecutive_actions()

    def _get_active_complication(self, name: str) -> Any | None:
        """Return an active complication instance by name, or None."""
        for comp in self._complication_registry.active_complications():
            if comp.name == name:
                return comp
        return None

    def get_active_complication_by_capability(self, capability: str) -> Any | None:
        """Return the first ACTIVE complication that declares the given capability, or None."""
        return next(
            (c for c in self._complication_registry.active_complications()
             if capability in getattr(c, "capabilities", [])),
            None,
        )

    # ── The Five Functions ────────────────────────────────────────────────────

    def ingest(
        self,
        *,
        data: dict[str, Any],
        provenance: dict[str, Any],
        purpose: str,
        subject_id: str,
        actor: str,
        idempotency_key: str | None = None,
        episode_id: str | None = None,
        correlation_id: str | None = None,
        model_context: dict[str, Any] | None = None,
    ) -> OutputEnvelope:
        return _ingest(
            data=data, provenance=provenance, purpose=purpose,
            subject_id=subject_id, actor=actor, ledger=self._ledger,
            consent_ledger=self._consent_ledger, graph=self._graph,
            idempotency_key=idempotency_key,
            idempotency_cache=self._idempotency_cache,
            episode_id=episode_id, correlation_id=correlation_id,
            model_context=model_context,
        )

    def query(
        self,
        *,
        purpose: str,
        subject_ids: list[str],
        actor: str,
        constraints: dict[str, Any] | None = None,
        classification_max: int = 0,
        episode_id: str | None = None,
        correlation_id: str | None = None,
        model_context: dict[str, Any] | None = None,
    ) -> OutputEnvelope:
        return _query(
            purpose=purpose, subject_ids=subject_ids, actor=actor,
            ledger=self._ledger, consent_ledger=self._consent_ledger,
            graph=self._graph, constraints=constraints,
            classification_max=classification_max,
            complication_registry=self._complication_registry,
            circuit_breakers=self._circuit_breakers,
            episode_id=episode_id, correlation_id=correlation_id,
            model_context=model_context,
        )

    def review(
        self,
        *,
        audit_id: str,
        actor: str,
        action: str | None = None,
        episode_id: str | None = None,
        correlation_id: str | None = None,
    ) -> OutputEnvelope:
        result = _review(
            audit_id=audit_id, action=action, actor=actor,
            ledger=self._ledger, review_store=self._review_store,
            episode_id=episode_id, correlation_id=correlation_id,
        )
        if action in ("approve", "veto") and result.status in ("ok", "error"):
            event_type = "review.approved" if action == "approve" else "review.vetoed"
            self._webhook_registry.dispatch(event_type, {"audit_id": audit_id, "actor": actor})
        # Reset agent consecutive action counter on approval
        if action == "approve" and result.status == "ok":
            for comp in self._complication_registry.active_complications():
                if hasattr(comp, "reset_consecutive_actions"):
                    comp.reset_consecutive_actions()
        return result

    def commit(
        self,
        *,
        event_type: str,
        payload: dict[str, Any],
        actor: str,
        idempotency_key: str | None = None,
        episode_id: str | None = None,
        correlation_id: str | None = None,
    ) -> OutputEnvelope:
        return _commit(
            event_type=event_type, payload=payload, actor=actor,
            ledger=self._ledger, idempotency_key=idempotency_key,
            idempotency_cache=self._idempotency_cache,
            episode_id=episode_id, correlation_id=correlation_id,
        )

    def replay(
        self,
        *,
        audit_id: str,
        actor: str,
        scope: list[str] | None = None,
        episode_id: str | None = None,
        correlation_id: str | None = None,
        model_context: dict[str, Any] | None = None,
    ) -> OutputEnvelope:
        return _replay(
            audit_id=audit_id, actor=actor, ledger=self._ledger,
            consent_ledger=self._consent_ledger, scope=scope,
            episode_id=episode_id, correlation_id=correlation_id,
            model_context=model_context,
        )

    def record_capture_gap(
        self,
        gap_type: str,
        actor: str,
        episode_id: str | None = None,
        reason: str | None = None,
        model_hint: str | None = None,
        extra: dict[str, object] | None = None,
    ) -> AuditEvent:
        """
        Declare that a capture-surface call (LLM, tool, MCP) was made
        outside the complication framework.

        This is the honest answer to the audit question: "an LLM was called
        but aevum-llm was not registered — is this an error or a known gap?"
        The developer calls this to make the gap auditable rather than invisible.

        The call is recorded as a capture.gap AuditEvent in the sigchain.
        An auditor can then see: "at this point in episode X, the operator
        declared an out-of-band call was made."

        Args:
            gap_type: "llm" | "mcp" | "tool" | "custom"
            actor:    The agent or component making the out-of-band call
            episode_id: Link this gap to an episode for forensic grouping
            reason:   Why the complication was bypassed (e.g. "direct_api_call",
                      "complication_not_registered", "testing")
            model_hint: Optional hint for what was called (e.g. "gpt-4.1")
                        — for auditor context only, not validated
            extra:    Additional structured context for the auditor

        Returns:
            The signed AuditEvent written to the sigchain
        """
        VALID_GAP_TYPES = ("llm", "mcp", "tool", "custom")
        if gap_type not in VALID_GAP_TYPES:
            raise ValueError(
                f"gap_type must be one of {VALID_GAP_TYPES}, got {gap_type!r}"
            )
        if not actor or not actor.strip():
            raise ValueError("actor must be a non-empty string")

        payload: dict[str, object] = {
            "gap_type": gap_type,
            "reason": reason or "unspecified",
        }
        if model_hint is not None:
            payload["model_hint"] = model_hint
        if extra:
            payload["extra"] = extra

        return self._ledger.append(
            event_type="capture.gap",
            payload=payload,
            actor=actor,
            episode_id=episode_id,
        )

    # ── Internal / testing hooks ──────────────────────────────────────────────

    def create_review(
        self,
        *,
        proposed_action: str,
        reason: str,
        actor: str,
        autonomy_level: int = 1,
        risk_assessment: str = "",
        deadline_iso: str | None = None,
    ) -> str:
        provisional_id = self._review_store.create(
            proposed_action=proposed_action, reason=reason, actor=actor,
            autonomy_level=autonomy_level, risk_assessment=risk_assessment,
            deadline_iso=deadline_iso,
        )
        self._ledger.append(
            event_type="review.created",
            payload={
                "audit_id": provisional_id,
                "proposed_action": proposed_action,
                "reason": reason,
                "autonomy_level": autonomy_level,
            },
            actor=actor,
        )
        return provisional_id

    def get_ledger_entries(self) -> list[dict[str, Any]]:
        return [
            {"audit_id": e.audit_id(), "event_type": e.event_type,
             "actor": e.actor, "payload": e.payload, "sequence": e.sequence}
            for e in self._ledger.all_events()
        ]

    def ledger_count(self) -> int:
        return self._ledger.count()

    def verify_sigchain(self) -> bool:
        return self._sigchain.verify_chain(self._ledger.all_events())
