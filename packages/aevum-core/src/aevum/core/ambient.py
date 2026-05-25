# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
AmbientContextReceipt — CVR "area microphone" equivalent for continuous system
state capture. Not tied to a specific agent action; provides forensic context
for post-incident reconstruction.

AmbientContextEncoder — COSE_Sign1 envelope for ambient context snapshots.
Uses content_type "application/aevum-ambient+cbor".

NOTE: Aevum does NOT automatically poll. SigChain.capture_ambient_context()
is a method callers invoke explicitly. Callers wanting 1 Hz sampling must
implement their own timer loop outside the library — background threads would
impose concurrency requirements the library cannot make safely.
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from typing import TYPE_CHECKING, Any

import cbor2
from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from aevum.core.audit.signer import Signer
    from aevum.core.tsa import TSAClient

logger = logging.getLogger(__name__)

_AEVUM_VERSION: str = "unknown"
try:
    from importlib.metadata import version as _pkg_version
    _AEVUM_VERSION = _pkg_version("aevum-core")
except Exception:  # noqa: BLE001
    pass

# COSE algorithm identifier for EdDSA (Ed25519) per RFC 9053.
_COSE_ALG_EDDSA = -8

# draft-ietf-cose-tsa-tst-header-parameter-08 label TBD; using integer 9 as placeholder.
_COSE_TST_HEADER_LABEL = 9

# Valid trigger values for AmbientContextReceipt.trigger
TRIGGER_SESSION_START = "SESSION_START"
TRIGGER_STATE_CHANGE = "STATE_CHANGE"
TRIGGER_PERIODIC = "PERIODIC"
TRIGGER_INCIDENT_LOCK = "INCIDENT_LOCK"
VALID_TRIGGERS = {
    TRIGGER_SESSION_START,
    TRIGGER_STATE_CHANGE,
    TRIGGER_PERIODIC,
    TRIGGER_INCIDENT_LOCK,
}


class AmbientContextReceipt(BaseModel):
    """
    Area-microphone snapshot of continuous system state and environmental signals.

    Captured independently of specific agent actions. Provides forensic context
    for post-incident reconstruction (FOQA-style continuous recording).

    Trigger values:
      SESSION_START  — one snapshot when a new agent session begins
      STATE_CHANGE   — when model_identity_hash, policy_version, or tool_allowlist_hash changes
      PERIODIC       — caller-driven interval (library does NOT poll automatically)
      INCIDENT_LOCK  — when a trigger escalates to the crash-protected tier
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    snapshot_id: str
    session_id: str
    captured_at: str
    aevum_version: str = Field(default_factory=lambda: _AEVUM_VERSION)

    # ── System state ──────────────────────────────────────────────────────────
    system_state_hash: str
    model_identity_hash: str
    policy_version: str
    tool_allowlist_hash: str
    memory_store_hash: str

    # ── Environmental signals (None if not measurable) ────────────────────────
    input_token_rate_per_min: float | None = None
    output_token_rate_per_min: float | None = None
    latency_p95_ms: float | None = None
    error_rate_pct: float | None = None
    cache_hit_rate_pct: float | None = None

    # ── Trigger ───────────────────────────────────────────────────────────────
    trigger: str

    # ── Chain linkage ─────────────────────────────────────────────────────────
    prior_snapshot_id: str | None = None

    def to_cbor_payload(self) -> bytes:
        """Serialize to CBOR with deterministic field ordering."""
        data = {
            "aevum_version": self.aevum_version,
            "cache_hit_rate_pct": self.cache_hit_rate_pct,
            "captured_at": self.captured_at,
            "error_rate_pct": self.error_rate_pct,
            "input_token_rate_per_min": self.input_token_rate_per_min,
            "latency_p95_ms": self.latency_p95_ms,
            "memory_store_hash": self.memory_store_hash,
            "model_identity_hash": self.model_identity_hash,
            "output_token_rate_per_min": self.output_token_rate_per_min,
            "policy_version": self.policy_version,
            "prior_snapshot_id": self.prior_snapshot_id,
            "session_id": self.session_id,
            "snapshot_id": self.snapshot_id,
            "system_state_hash": self.system_state_hash,
            "tool_allowlist_hash": self.tool_allowlist_hash,
            "trigger": self.trigger,
        }
        return cbor2.dumps(dict(sorted(data.items())))


def _compute_system_state_hash(
    model_id: str,
    policy_version: str,
    tool_allowlist_hash: str,
) -> str:
    """SHA3-256(model_id | policy_version | tool_allowlist_hash). UNKNOWN if any is missing."""
    if "UNKNOWN" in (model_id, policy_version, tool_allowlist_hash):
        return "UNKNOWN"
    raw = f"{model_id}|{policy_version}|{tool_allowlist_hash}".encode()
    return hashlib.sha3_256(raw).hexdigest()


class AmbientContextEncoder:
    """
    Encodes an AmbientContextReceipt as a COSE_Sign1 envelope.

    Same pattern as ReceiptEncoder. Uses:
      - alg=-8 (EdDSA/Ed25519)
      - content_type: "application/aevum-ambient+cbor"
      - sub: "urn:aevum:ambient:<snapshot_id[:16]>"
      - iss: "did:web:<issuer_host>"
      - iat: int(time.time())

    In dev_mode (AEVUM_DEV=1): no TSA calls, no network I/O.
    """

    def __init__(
        self,
        signer: Signer,
        tsa_client: TSAClient | None = None,
        dev_mode: bool = False,
        issuer_host: str = "aevum.local",
    ) -> None:
        self._signer = signer
        self._tsa_client = tsa_client
        self._dev_mode = dev_mode
        self._issuer_host = issuer_host

    def encode(self, snapshot: AmbientContextReceipt) -> bytes:
        """
        Encode an AmbientContextReceipt as a COSE_Sign1 envelope.

        Returns raw CBOR bytes of the 4-element COSE_Sign1 array.
        """
        issuer_uri = "did:web:" + self._issuer_host
        subject_uri = "urn:aevum:ambient:" + snapshot.snapshot_id[:16]
        issued_at = int(time.time())

        protected_header: dict[Any, Any] = {
            1: _COSE_ALG_EDDSA,
            3: "application/aevum-ambient+cbor",
            4: b"aevum-issuer-v1",
            # SCITT-profile protected header fields
            # draft-ietf-scitt-architecture-22 §4.1 — iss/sub labels TBD
            # Using CBOR text key strings until integer labels are standardized.
            # When draft publishes as RFC: update to assigned integer labels.
            "iss": issuer_uri,
            "sub": subject_uri,
            "iat": issued_at,
        }
        protected_bstr = cbor2.dumps(protected_header)
        payload_bstr = snapshot.to_cbor_payload()

        sig_structure = cbor2.dumps(["Signature1", protected_bstr, b"", payload_bstr])
        digest = hashlib.sha3_256(sig_structure).digest()
        signature_bytes = self._signer.sign(digest)

        unprotected: dict[int, Any] = {}
        if not self._dev_mode and self._tsa_client is not None:
            try:
                tsa_token = self._tsa_client.timestamp(payload_bstr)
                if tsa_token is not None:
                    unprotected[_COSE_TST_HEADER_LABEL] = tsa_token.token_bytes
            except Exception as exc:  # noqa: BLE001
                logger.warning("AmbientContextEncoder: TSA timestamp failed (non-blocking): %s", exc)

        cose_sign1 = [protected_bstr, unprotected, payload_bstr, signature_bytes]
        return cbor2.dumps(cose_sign1)

    @classmethod
    def from_env(cls) -> AmbientContextEncoder:
        """
        Construct from environment variables.
        AEVUM_DEV=1 → dev_mode=True, no TSA client.
        AEVUM_ISSUER_HOST → issuer hostname for SCITT iss field (default: aevum.local).
        """
        from aevum.core.audit.signer import InProcessSigner
        from aevum.core.tsa import TSAClient

        dev_mode = os.environ.get("AEVUM_DEV", "").strip() == "1"
        issuer_host = os.environ.get("AEVUM_ISSUER_HOST", "aevum.local")
        signer: Signer = InProcessSigner()
        tsa_client: TSAClient | None = None if dev_mode else TSAClient()
        return cls(
            signer=signer,
            tsa_client=tsa_client,
            dev_mode=dev_mode,
            issuer_host=issuer_host,
        )
