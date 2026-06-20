# SPDX-License-Identifier: Apache-2.0
"""
Engine — the governed membrane: every operation passes through the five unconditional
barriers before reaching the knowledge graph or the policy engine.

This module wires together the core kernel components:
  episodic ledger  (InMemoryLedger backed by Sigchain)
  consent ledger   (ConsentLedger or DevModeConsentLedger)
  knowledge graph  (GraphStore — InMemoryGraphStore, Oxigraph, or Postgres)
  policy bridge    (Cedar + optional OPA HTTP sidecar)
  complication registry  (signed, approved, circuit-broken extensions)

And exposes the five public functions (all return OutputEnvelope — never raise on denial):
  ingest  (RELATE)   — write data through the governed membrane
  query   (NAVIGATE) — traverse the graph for a declared purpose
  review  (GOVERN)   — present context for a human decision point
  commit  (REMEMBER) — append event to the episodic ledger directly
  replay             — reconstruct any past decision from the episodic ledger

Evaluation order for every operation: unconditional barriers → policy engine → graph.
"""

from __future__ import annotations

import logging
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
from aevum.core.policy import NullPolicyEngine, PolicyEngine
from aevum.core.policy.bridge import PolicyBridge
from aevum.core.protocols.audit_ledger import AuditLedgerProtocol
from aevum.core.protocols.consent_ledger import ConsentLedgerProtocol
from aevum.core.protocols.graph_store import GraphStore

_logger = logging.getLogger(__name__)


def _resolve_default_policy_engine(*, dev_mode: bool = False) -> PolicyEngine:
    """
    Load Cedar if available (production), fall back to Null.
    In dev mode: always return NullPolicyEngine without attempting Cedar.
    """
    if dev_mode:
        return NullPolicyEngine()
    try:
        from aevum.core.policy.cedar_engine import CedarPolicyEngine
        return CedarPolicyEngine.default()
    except (ImportError, RuntimeError):
        return NullPolicyEngine()


class Engine:
    """The Aevum context kernel — governed membrane between raw data and AI consumers.

    Every ingest/query/review/commit/replay call passes through the five unconditional
    barriers (barriers.py) before any graph write or policy check. Barriers are unconditional
    and non-configurable; the policy engine is configurable. Evaluation order:
      unconditional barriers → policy engine → knowledge graph

    Default component selection on construction:
      graph_store:    InMemoryGraphStore (warns — use oxigraph/postgres for persistence)
      sigchain:       Sigchain() with InProcessSigner (Ed25519 in-process key; see ADR-004)
      consent_ledger: ConsentLedger (production) or DevModeConsentLedger (AEVUM_DEV=1)
      policy_engine:  CedarPolicyEngine if [cedar] extra present, else NullPolicyEngine
      ledger:         InMemoryLedger wrapping the sigchain

    See THREAT_MODEL.md — Assumption 4 for the in-memory storage risk statement.
    """

    def __init__(
        self,
        *,
        graph_store: GraphStore | None = None,
        opa_url: str | None = None,
        sigchain: Sigchain | None = None,
        consent_ledger: ConsentLedgerProtocol | None = None,
        ledger: AuditLedgerProtocol | None = None,
        policy_engine: PolicyEngine | None = None,
        signing_posture: str | None = None,
    ) -> None:
        from aevum.core.dev_mode import (
            DevModeConsentLedger,
            is_dev_mode,
            warn_dev_startup,
        )
        _dev = is_dev_mode()

        self._sigchain = sigchain or Sigchain()
        self._ledger = ledger or InMemoryLedger(self._sigchain)
        if consent_ledger is not None:
            self._consent_ledger: ConsentLedgerProtocol = consent_ledger
        elif _dev:
            self._consent_ledger = DevModeConsentLedger()
        else:
            self._consent_ledger = ConsentLedger()
        self._graph: GraphStore = graph_store or InMemoryGraphStore()
        if graph_store is None and not _dev:
            _logger.warning(
                "Engine initialized with in-memory storage. "
                "All data, the sigchain, and consent records will be lost on "
                "process restart. "
                "Use aevum-store-oxigraph or aevum-store-postgres for any "
                "persistent workload. "
                "See THREAT_MODEL.md — Assumption 4."
            )
        if _dev:
            warn_dev_startup()
        self._policy = PolicyBridge(opa_url=opa_url)
        self._policy_engine: PolicyEngine = policy_engine or _resolve_default_policy_engine(dev_mode=_dev)
        self._review_store = ReviewStore()
        self._idempotency_cache: dict[str, OutputEnvelope] = {}

        self._complication_registry = ComplicationRegistry()
        self._circuit_breakers: dict[str, CircuitBreaker] = {}
        self._manifest_validator = ManifestValidator()
        self._conflict_detector = ConflictDetector()
        self._webhook_registry = WebhookRegistry(ledger=self._ledger)

        if signing_posture == "classical-only":
            self._ledger.append(
                event_type="posture.attestation",
                payload={
                    "signing_posture": "classical-only",
                    "scheme": "ed25519",
                    "post_quantum": False,
                    "reason": "explicit operator opt-in via AEVUM_SIGNING_POSTURE=classical-only",
                    "note": "Ed25519-only — no ML-DSA-65 / no post-quantum protection on this chain.",
                },
                actor="aevum-core",
            )

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
            instance: A Complication instance.
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

        # Inject ledger observer for telemetry complications (e.g. AevumOTelBridge)
        if hasattr(instance, "set_event_observer"):
            instance.set_event_observer(self._ledger)

        # Log to ledger
        self._ledger.append(
            event_type="complication.installed",
            payload={
                "name": name,
                "version": manifest.get("version", ""),
                "actor_id": manifest.get("actor_id", name),
            },
            actor="aevum-core",
        )

        if auto_approve:
            self.approve_complication(name)

    def approve_complication(self, name: str, *, approved_by: str = "aevum-core") -> None:
        """Admin approval: PENDING → APPROVED → ACTIVE."""
        self._complication_registry.approve(name)
        self._ledger.append(
            event_type="complication.approved",
            payload={"name": name, "approved_by": approved_by},
            actor=approved_by,
        )

    def suspend_complication(self, name: str, *, suspended_by: str = "aevum-core",
                             reason: str = "") -> None:
        """Admin suspension: ACTIVE → SUSPENDED."""
        self._complication_registry.suspend(name)
        self._ledger.append(
            event_type="complication.suspended",
            payload={"name": name, "suspended_by": suspended_by, "reason": reason},
            actor=suspended_by,
        )

    def resume_complication(self, name: str, *, resumed_by: str = "aevum-core") -> None:
        """Admin resume: SUSPENDED → ACTIVE."""
        self._complication_registry.resume(name)
        self._ledger.append(
            event_type="complication.resumed",
            payload={"name": name, "resumed_by": resumed_by},
            actor=resumed_by,
        )

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
        session: Any = None,        # aevum.core.session.Session | None
    ) -> OutputEnvelope:
        """RELATE — write data through the governed membrane to the knowledge graph.

        Evaluation order (barriers fire before any graph write):
          1. Barrier 5 (Provenance): deny if provenance.source_id is absent or empty.
          2. Barrier 3 (Consent): deny if no active consent grant for this subject/operation.
          3. Barrier 1 (Crisis): halt if payload contains crisis keywords.
          4. Policy engine: Cedar/OPA permission check.
          5. Knowledge graph write.
          6. Episodic ledger append.

        Provenance fires before consent because chain-of-custody must be established
        before Cedar can evaluate data-origin attributes in a consent policy expression.

        Returns:
            OutputEnvelope — status "ok" on success, "error" on barrier/policy denial,
            "crisis" if Barrier 1 fired. Never raises on denial; inspect envelope.status.
        """
        import time
        t0 = time.monotonic()
        result = _ingest(
            data=data, provenance=provenance, purpose=purpose,
            subject_id=subject_id, actor=actor, ledger=self._ledger,
            consent_ledger=self._consent_ledger, graph=self._graph,
            idempotency_key=idempotency_key,
            idempotency_cache=self._idempotency_cache,
            episode_id=episode_id, correlation_id=correlation_id,
            model_context=model_context,
            policy_engine=self._policy_engine,
        )
        if session is not None and hasattr(session, "record_relate_event"):
            try:
                from aevum.core.session_record import SessionEvent
                in_h = SessionEvent.hash_payload({"data": data, "purpose": purpose, "subject_id": subject_id})
                out_h = SessionEvent.hash_payload(result.data or {})
                fact_id = (result.data or {}).get("typed_fact", {}).get("fact_id") if result.data else None
                session.record_relate_event(
                    in_h, out_h,
                    fact_id=fact_id,
                    latency_ms=int((time.monotonic() - t0) * 1000),
                )
            except Exception as exc:  # noqa: BLE001
                _logger.error("session event recording failed (ingest): %s", exc)
        return result

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
        capture_witness: bool = True,
        session: Any = None,        # aevum.core.session.Session | None
    ) -> OutputEnvelope:
        """NAVIGATE — traverse the knowledge graph for a declared purpose.

        Evaluation order:
          1. Barrier 1 (Crisis): halt if the query purpose contains crisis keywords.
          2. Barrier 3 (Consent): deny if no active consent grant for this subject/operation.
          3. Policy engine (Cedar/OPA): ABAC check for action="navigate".
          4. Barrier 2 (Classification Ceiling): BLOCK the whole query if any requested
             subject EXISTS and exceeds the actor's clearance (classification_max).
             Absent subjects are not a barrier event — they yield no rows.
          5. Graph traversal — every returned subject is within clearance by construction.
          6. Optional: Witness capture seals the result hash against the consent ledger
             sequence at query time, protecting against TOCTOU revocation.

        Returns:
            OutputEnvelope — status "ok" (full results), "error" with
            error_code="classification_blocked" (Barrier 2 block), "error" with
            error_code="consent_required" (Barrier 3 denial), or "crisis". Never raises.
        """
        import time
        t0 = time.monotonic()
        result = _query(
            purpose=purpose, subject_ids=subject_ids, actor=actor,
            ledger=self._ledger, consent_ledger=self._consent_ledger,
            graph=self._graph, constraints=constraints,
            classification_max=classification_max,
            complication_registry=self._complication_registry,
            circuit_breakers=self._circuit_breakers,
            episode_id=episode_id, correlation_id=correlation_id,
            model_context=model_context,
            capture_witness=capture_witness,
            policy_engine=self._policy_engine,
        )
        if session is not None and hasattr(session, "record_navigate_event"):
            try:
                from aevum.core.session_record import SessionEvent
                in_h = SessionEvent.hash_payload({"purpose": purpose, "subject_ids": subject_ids})
                out_h = SessionEvent.hash_payload(result.data or {})
                session.record_navigate_event(
                    in_h, out_h,
                    latency_ms=int((time.monotonic() - t0) * 1000),
                )
            except Exception as exc:  # noqa: BLE001
                _logger.error("session event recording failed (query): %s", exc)
        return result

    def review(
        self,
        *,
        audit_id: str,
        actor: str,
        action: str | None = None,
        episode_id: str | None = None,
        correlation_id: str | None = None,
        session: Any = None,        # aevum.core.session.Session | None
    ) -> OutputEnvelope:
        """GOVERN — present a pending action for human review at a checkpoint.

        review() implements the veto-as-default contract: a pending action that is not
        explicitly approved is treated as vetoed. Timeout = veto, not approval. This is
        the primary defence against OWASP ASI06 (Human-in-the-Loop Bypass): the system
        defaults to the safe path (halt) rather than the permissive path (proceed).

        S-15 (AUTOMATION_BIAS_WARNING): every consequential or irreversible GOVERN
        checkpoint must emit the automation bias warning. This friction is intentional —
        the ICLR 2025 finding (84.30% mixed-attack success, humans correct ~50% under
        automation bias) is the justification.

        action=None means "present for review"; action="approve" or "veto" resolves it.
        Resolving a review resets the AgentComplication consecutive-action counter.

        Returns:
            OutputEnvelope — status "ok" on present/approve/veto, "error" if audit_id
            not found or action is invalid. Never raises on policy denial.
        """
        import time
        t0 = time.monotonic()
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
        if session is not None and hasattr(session, "record_govern_event"):
            try:
                from aevum.core.session_record import SessionEvent
                in_h = SessionEvent.hash_payload({"audit_id": audit_id, "action": action})
                out_h = SessionEvent.hash_payload(result.data or {})
                session.record_govern_event(
                    in_h, out_h,
                    checkpoint_id=audit_id,
                    latency_ms=int((time.monotonic() - t0) * 1000),
                )
            except Exception as exc:  # noqa: BLE001
                _logger.error("session event recording failed (review): %s", exc)
        return result

    def commit(
        self,
        *,
        event_type: str,
        payload: dict[str, Any],
        actor: str,
        witness: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
        episode_id: str | None = None,
        correlation_id: str | None = None,
        principal_identity: str | None = None,
        principal_claims: dict[str, Any] | None = None,
        commitment_key_id: str | None = None,
    ) -> OutputEnvelope:
        """REMEMBER — append an event to the episodic ledger (the sigchain directly).

        commit() is the low-level ledger write, distinct from Session._remember() which
        seals a full episode. Use commit() when you need to record a single discrete event
        without the full session lifecycle (e.g., a standalone policy decision, a break-glass
        activation, or a system health checkpoint).

        After commit() returns, the event is signed, chained, and immutable (I1-APPEND_ONLY).
        Any idempotency_key provided causes a cached envelope to be returned for duplicate
        calls, preventing double-writes in at-least-once delivery scenarios.

        principal_identity / principal_claims / commitment_key_id bind this event to a
        verified external credential identity (P2-IDENTITY-V2) — pass these only when the
        underlying ledger was constructed with a CommitmentKeyStore (see
        aevum.core.audit.commitment_key_store). The raw commitment key never crosses this
        method's signature; only commitment_key_id does (HO-G-PLUMB SR1).

        Returns:
            OutputEnvelope — status "ok" with the signed AuditEvent audit_id in data,
            or "error" if the ledger write failed. Never raises on policy denial.
        """
        return _commit(
            event_type=event_type, payload=payload, actor=actor,
            ledger=self._ledger, graph=self._graph, witness=witness,
            idempotency_key=idempotency_key,
            idempotency_cache=self._idempotency_cache,
            episode_id=episode_id, correlation_id=correlation_id,
            principal_identity=principal_identity,
            principal_claims=principal_claims,
            commitment_key_id=commitment_key_id,
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
        """Reconstruct any past decision faithfully from the episodic ledger.

        replay() is the primary forensic tool. It reads the signed AuditEvent identified
        by audit_id from the episodic ledger and returns its full context — the payload,
        the actor, the consent state at that time, and the cryptographic proof of integrity.

        replay() does NOT re-execute side effects (no graph writes, no LLM calls, no TSA
        requests). It reconstructs the record as it was signed at the time of the original
        decision. This is what makes aevum "replay-first": any past decision can be
        reconstructed and verified by an independent investigator without trusting the
        operator's current state.

        Consent is checked before returning the replay — an actor cannot replay a record
        for a subject they are not currently consented to query.

        Returns:
            OutputEnvelope — status "ok" with the reconstructed decision in data,
            "error" if audit_id not found or consent denied. Never raises on denial.
        """
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
        but no LLM complication was registered — is this an expected gap?"
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
        import dataclasses
        result = []
        for e in self._ledger.all_events():
            d = dataclasses.asdict(e)
            d["audit_id"] = e.audit_id()
            result.append(d)
        return result

    def ledger_count(self) -> int:
        return self._ledger.count()

    def verify_sigchain(self) -> bool:
        return self._sigchain.verify_chain(self._ledger.all_events())
