# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
AevumReceipt — PROV-AGENT + DSSAD vocabulary payload for the black box receipt layer.

Every receipt is serializable to CBOR (RFC 8949) via cbor2 and is the payload
that goes into the COSE_Sign1 envelope produced by ReceiptEncoder.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import cbor2
from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from aevum.core.audit.event import AuditEvent

logger = logging.getLogger(__name__)

_AEVUM_VERSION: str = "unknown"
try:
    from importlib.metadata import version as _pkg_version
    _AEVUM_VERSION = _pkg_version("aevum-core")
except Exception:  # noqa: BLE001
    pass


class AevumReceipt(BaseModel):
    """
    Black box receipt payload.

    Sigchain identity fields map directly from AuditEvent.
    PROV-AGENT fields (arXiv 2508.02866) add semantic context the caller provides.
    DSSAD-equivalent fields (UNECE WP.29 UN R157) capture handoff events.
    Delegation fields map W3C PROV actedOnBehalfOf.
    """

    # ── Sigchain identity ─────────────────────────────────────────────────────
    sigchain_entry_hash: str
    action: str
    principal: str
    prior_hash: str
    occurred_at: str
    agent_id: str
    sequence: int
    aevum_version: str = Field(default_factory=lambda: _AEVUM_VERSION)

    # ── PROV-AGENT fields (arXiv 2508.02866, Section 4) ───────────────────────
    model_identity_hash: str = "UNKNOWN"
    prompt_hash: str = "UNKNOWN"
    retrieval_corpus_ver: str = "NONE"
    policy_version: str = "UNKNOWN"
    tool_allowlist_hash: str = "UNKNOWN"

    # ── DSSAD-equivalent (UNECE WP.29 UN R157 mapping) ────────────────────────
    handoff_type: str | None = None
    handoff_from_agent_id: str | None = None
    handoff_to_agent_id: str | None = None
    human_override_action: str | None = None

    # ── Delegation chain (W3C PROV actedOnBehalfOf) ───────────────────────────
    delegated_by: str | None = None
    delegation_scope: str | None = None

    # ── Consent / barrier fields ──────────────────────────────────────────────
    consent_token_id: str | None = None
    barrier_evaluations: dict[str, Any] = Field(default_factory=dict)

    def to_cbor_payload(self) -> bytes:
        """Serialize to CBOR with deterministic field ordering."""
        if self.model_identity_hash == "UNKNOWN":
            logger.debug(
                "AevumReceipt: model_identity_hash is UNKNOWN for agent=%s action=%s — "
                "wire model hash capture into your adapter to enable full PROV-AGENT provenance.",
                self.agent_id,
                self.action,
            )
        data = {
            "sigchain_entry_hash": self.sigchain_entry_hash,
            "action": self.action,
            "principal": self.principal,
            "prior_hash": self.prior_hash,
            "occurred_at": self.occurred_at,
            "agent_id": self.agent_id,
            "sequence": self.sequence,
            "aevum_version": self.aevum_version,
            "model_identity_hash": self.model_identity_hash,
            "prompt_hash": self.prompt_hash,
            "retrieval_corpus_ver": self.retrieval_corpus_ver,
            "policy_version": self.policy_version,
            "tool_allowlist_hash": self.tool_allowlist_hash,
            "handoff_type": self.handoff_type,
            "handoff_from_agent_id": self.handoff_from_agent_id,
            "handoff_to_agent_id": self.handoff_to_agent_id,
            "human_override_action": self.human_override_action,
            "delegated_by": self.delegated_by,
            "delegation_scope": self.delegation_scope,
            "consent_token_id": self.consent_token_id,
            "barrier_evaluations": self.barrier_evaluations,
        }
        return cbor2.dumps(dict(sorted(data.items())))

    @classmethod
    def from_sigchain_event(
        cls,
        event: AuditEvent,
        **kwargs: Any,
    ) -> AevumReceipt:
        """
        Construct an AevumReceipt from an AuditEvent plus optional PROV-AGENT kwargs.

        The caller provides PROV-AGENT fields (model_identity_hash, prompt_hash, etc.)
        that the sigchain itself does not have. These default to UNKNOWN/NONE/None if
        not provided — the sigchain is ground truth for identity; the receipt adds
        semantic context the caller knows.
        """
        import hashlib
        import json

        # Compute sigchain_entry_hash over all event identity fields
        fields = {
            "event_id": event.event_id,
            "sequence": event.sequence,
            "event_type": event.event_type,
            "actor": event.actor,
            "prior_hash": event.prior_hash,
            "payload_hash": event.payload_hash,
        }
        canonical = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()
        entry_hash = hashlib.sha3_256(canonical).hexdigest()

        return cls(
            sigchain_entry_hash=entry_hash,
            action=event.event_type,
            principal=event.actor,
            prior_hash=event.prior_hash,
            occurred_at=event.valid_from,
            agent_id=kwargs.get("agent_id", event.actor),
            sequence=event.sequence,
            aevum_version=_AEVUM_VERSION,
            model_identity_hash=kwargs.get("model_identity_hash", "UNKNOWN"),
            prompt_hash=kwargs.get("prompt_hash", "UNKNOWN"),
            retrieval_corpus_ver=kwargs.get("retrieval_corpus_ver", "NONE"),
            policy_version=kwargs.get("policy_version", "UNKNOWN"),
            tool_allowlist_hash=kwargs.get("tool_allowlist_hash", "UNKNOWN"),
            handoff_type=kwargs.get("handoff_type"),
            handoff_from_agent_id=kwargs.get("handoff_from_agent_id"),
            handoff_to_agent_id=kwargs.get("handoff_to_agent_id"),
            human_override_action=kwargs.get("human_override_action"),
            delegated_by=kwargs.get("delegated_by"),
            delegation_scope=kwargs.get("delegation_scope"),
            consent_token_id=kwargs.get("consent_token_id"),
            barrier_evaluations=kwargs.get("barrier_evaluations", {}),
        )
