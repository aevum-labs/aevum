"""
Sigchain — Ed25519 signing and SHA3-256 chaining. Spec Section 06.
Phase 1: adds ImmutableLedgerError, DualSigner integration, TSA integration.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import logging
import os
import time
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)

from aevum.core.audit.event import AuditEvent
from aevum.core.audit.hlc import now as hlc_now
from aevum.core.audit.signer import InProcessSigner, Signer

if TYPE_CHECKING:
    from aevum.publish.encoder import ReceiptEncoder

    from aevum.core.ambient import AmbientContextEncoder, AmbientContextReceipt
    from aevum.core.signing import DualSigner
    from aevum.core.tsa import TSAClient

logger = logging.getLogger(__name__)

GENESIS_HASH = hashlib.sha3_256(b"aevum:genesis").hexdigest()


class ImmutableLedgerError(Exception):
    """
    Raised when code attempts to modify or delete an audit chain entry.
    The audit chain is append-only. This error is permanent and intentional.
    """


def _uuid7() -> str:
    """UUID version 7 (time-ordered). Inline — no external dep."""
    ts_ms = int(time.time() * 1000) & 0xFFFFFFFFFFFF
    rand = int.from_bytes(os.urandom(10), "big")
    rand_a = (rand >> 62) & 0x0FFF
    rand_b = rand & 0x3FFFFFFFFFFFFFFF
    hi = (ts_ms << 16) | 0x7000 | rand_a
    lo = 0x8000000000000000 | rand_b
    h = f"{hi:016x}{lo:016x}"
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


class Sigchain:
    """Per-node Ed25519 signing chain with optional Phase 1 dual-sig + TSA. Append-only by design."""

    def __init__(
        self,
        signer: Signer | None = None,
        # Backwards-compatible: wraps in InProcessSigner automatically
        private_key: object | None = None,  # Ed25519PrivateKey | None
        key_id: str | None = None,
        initial_sequence: int = 0,
        initial_prior_hash: str = GENESIS_HASH,
        # Phase 1 additions — optional
        dual_signer: DualSigner | None = None,
        tsa_client: TSAClient | None = None,
        # Phase 1A: COSE_Sign1 receipt encoder — optional, non-blocking
        receipt_encoder: ReceiptEncoder | None = None,
        # Phase 1B: ambient context encoder — optional, caller-driven
        ambient_encoder: AmbientContextEncoder | None = None,
    ) -> None:
        if signer is not None:
            self._signer = signer
        elif private_key is not None:
            self._signer = InProcessSigner(
                private_key=private_key,
                key_id=key_id,
                provenance_override="external",
            )
        else:
            self._signer = InProcessSigner()

        self._sequence: int = initial_sequence
        self._prior_hash: str = initial_prior_hash
        self._dual_signer = dual_signer
        self._tsa_client = tsa_client
        self._receipt_encoder = receipt_encoder
        self._ambient_encoder = ambient_encoder

    @property
    def key_id(self) -> str:
        return self._signer.key_id

    @property
    def key_provenance(self) -> str:
        return self._signer.provenance

    @property
    def public_key(self) -> Ed25519PublicKey:
        signer = self._signer
        # Access inner key for InProcessSigner (the only case where we need Ed25519PublicKey)
        if isinstance(signer, InProcessSigner):
            return signer._private_key.public_key()
        raise NotImplementedError(
            "public_key property only available for InProcessSigner; "
            "use public_key_bytes() for external signers."
        )

    def checkpoint(self) -> tuple[int, str]:
        return (self._sequence, self._prior_hash)

    def restore(self, checkpoint: tuple[int, str]) -> None:
        self._sequence, self._prior_hash = checkpoint

    def _sign(self, fields: dict[str, Any]) -> str:
        canonical = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()
        # Sign SHA3-256(canonical) — enables prehashed external signing
        digest = hashlib.sha3_256(canonical).digest()
        sig_bytes = self._signer.sign(digest)
        return base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode()

    def new_event(
        self,
        *,
        event_type: str,
        payload: dict[str, Any],
        actor: str,
        episode_id: str | None = None,
        causation_id: str | None = None,
        correlation_id: str | None = None,
        trace_id: str | None = None,
        span_id: str | None = None,
        valid_from: str | None = None,
        valid_to: str | None = None,
    ) -> AuditEvent:
        """Append a new signed event to the chain."""
        self._sequence += 1
        event_id = _uuid7()
        ep_id = episode_id or _uuid7()
        vf = valid_from or datetime.datetime.now(datetime.UTC).isoformat()
        ts = hlc_now()
        payload_hash = AuditEvent.hash_payload(payload)
        prior = self._prior_hash

        signing_fields: dict[str, Any] = {
            "event_id": event_id,
            "episode_id": ep_id,
            "sequence": self._sequence,
            "event_type": event_type,
            "schema_version": "1.0",
            "valid_from": vf,
            "valid_to": valid_to,
            "system_time": ts,
            "causation_id": causation_id,
            "correlation_id": correlation_id,
            "actor": actor,
            "trace_id": trace_id,
            "span_id": span_id,
            "payload_hash": payload_hash,
            "prior_hash": prior,
            "signer_key_id": self._signer.key_id,
        }
        canonical = json.dumps(signing_fields, sort_keys=True, separators=(",", ":")).encode()
        signature = base64.urlsafe_b64encode(
            self._signer.sign(hashlib.sha3_256(canonical).digest())
        ).rstrip(b"=").decode()

        # Phase 1: dual-sig + TSA (belt-and-suspenders, non-blocking)
        ed25519_sig_hex: str | None = None
        mldsa65_sig_hex: str | None = None
        ed25519_pub_hex: str | None = None
        mldsa65_pub_hex: str | None = None
        tsa_url: str | None = None
        tsa_token_hex: str | None = None

        if self._dual_signer is not None:
            try:
                from aevum.core.signing import DualSigner
                dual_sig = self._dual_signer.sign(canonical)
                DualSigner.verify(canonical, dual_sig)  # belt-and-suspenders
                ed25519_sig_hex = dual_sig.ed25519_sig.hex()
                mldsa65_sig_hex = dual_sig.mldsa65_sig.hex()
                ed25519_pub_hex = dual_sig.ed25519_pub.hex()
                mldsa65_pub_hex = dual_sig.mldsa65_pub.hex()
            except Exception as exc:
                logger.error("Dual-sig failed on new chain entry: %s", exc)

            if self._tsa_client is not None:
                try:
                    tsa_token = self._tsa_client.timestamp(canonical)
                    if tsa_token is not None:
                        tsa_url = tsa_token.tsa_url
                        tsa_token_hex = tsa_token.token_bytes.hex()
                except Exception as exc:
                    logger.warning("TSA timestamp failed (non-blocking): %s", exc)

        event = AuditEvent(
            event_id=event_id,
            episode_id=ep_id,
            sequence=self._sequence,
            event_type=event_type,
            schema_version="1.0",
            valid_from=vf,
            valid_to=valid_to,
            system_time=ts,
            causation_id=causation_id,
            correlation_id=correlation_id,
            actor=actor,
            trace_id=trace_id,
            span_id=span_id,
            payload=payload,
            payload_hash=payload_hash,
            prior_hash=prior,
            signature=signature,
            signer_key_id=self._signer.key_id,
            ed25519_sig=ed25519_sig_hex,
            mldsa65_sig=mldsa65_sig_hex,
            ed25519_pub=ed25519_pub_hex,
            mldsa65_pub=mldsa65_pub_hex,
            tsa_url=tsa_url,
            tsa_token=tsa_token_hex,
            key_scheme="ed25519",
        )
        self._prior_hash = AuditEvent.hash_event_for_chain(event)

        # Phase 1A: attach COSE_Sign1 receipt bytes if encoder is configured
        if self._receipt_encoder is not None:
            try:
                from aevum.core.receipt import AevumReceipt
                receipt = AevumReceipt.from_sigchain_event(event)
                receipt_cbor = self._receipt_encoder.encode(receipt)
                import dataclasses
                event = dataclasses.replace(event, receipt_cbor=receipt_cbor)
            except Exception as exc:
                logger.warning("Receipt encoding failed (non-blocking): %s", exc)

        return event

    def verify_chain(self, events: list[AuditEvent]) -> bool:
        """Verify entire chain from genesis. Returns True if intact."""
        # Obtain public key bytes and reconstruct Ed25519PublicKey for verification
        pub_key_bytes = self._signer.public_key_bytes()
        public_key = Ed25519PublicKey.from_public_bytes(pub_key_bytes)

        expected_prior = GENESIS_HASH
        for event in events:
            if event.prior_hash != expected_prior:
                return False
            if AuditEvent.hash_payload(event.payload) != event.payload_hash:
                return False
            signing_fields: dict[str, Any] = {
                "event_id": event.event_id,
                "episode_id": event.episode_id,
                "sequence": event.sequence,
                "event_type": event.event_type,
                "schema_version": event.schema_version,
                "valid_from": event.valid_from,
                "valid_to": event.valid_to,
                "system_time": event.system_time,
                "causation_id": event.causation_id,
                "correlation_id": event.correlation_id,
                "actor": event.actor,
                "trace_id": event.trace_id,
                "span_id": event.span_id,
                "payload_hash": event.payload_hash,
                "prior_hash": event.prior_hash,
                "signer_key_id": event.signer_key_id,
            }
            canonical = json.dumps(
                signing_fields, sort_keys=True, separators=(",", ":")
            ).encode()
            # Verify against SHA3-256 digest of canonical bytes
            digest = hashlib.sha3_256(canonical).digest()
            # Phase C-1: key_scheme selects the verifier. "ed25519" is the only
            # active scheme; "ed25519+ml-dsa-65" is reserved for the future hybrid
            # implementation. Envelopes without the field default to "ed25519".
            scheme = getattr(event, "key_scheme", "ed25519")
            if scheme not in ("ed25519", "ed25519+ml-dsa-65"):
                logger.warning("Unknown key_scheme %r — falling back to ed25519", scheme)
            try:
                sig_bytes = base64.urlsafe_b64decode(event.signature + "==")
                public_key.verify(sig_bytes, digest)
            except Exception:
                return False

            # Phase 1: verify dual-sig if present on this entry
            if event.mldsa65_sig is not None and self._dual_signer is not None:
                try:
                    from aevum.core.signing import DualSignature, DualSigner
                    if (event.ed25519_sig is not None
                            and event.ed25519_pub is not None
                            and event.mldsa65_pub is not None):
                        dual_sig = DualSignature(
                            ed25519_sig=bytes.fromhex(event.ed25519_sig),
                            mldsa65_sig=bytes.fromhex(event.mldsa65_sig),
                            ed25519_pub=bytes.fromhex(event.ed25519_pub),
                            mldsa65_pub=bytes.fromhex(event.mldsa65_pub),
                        )
                        DualSigner.verify(canonical, dual_sig)
                except Exception:
                    return False

            expected_prior = AuditEvent.hash_event_for_chain(event)
        return True

    def capture_ambient_context(
        self,
        *,
        trigger: str,
        session_id: str,
        **env_signals: object,
    ) -> AmbientContextReceipt | None:
        """
        Capture an ambient context snapshot for this session.

        Returns None if no ambient_encoder was provided (backward compat).

        Callers are responsible for invocation timing:
          SESSION_START  — call once when a new agent session begins
          STATE_CHANGE   — call when model_identity_hash, policy_version,
                           or tool_allowlist_hash changes
          PERIODIC       — callers may poll at 1 Hz for high-fidelity FOQA analytics;
                           the library does NOT poll automatically (no background threads)
          INCIDENT_LOCK  — call when a trigger escalates to the crash-protected tier

        env_signals kwargs accepted:
          model_identity_hash, policy_version, tool_allowlist_hash,
          memory_store_hash, input_token_rate_per_min, output_token_rate_per_min,
          latency_p95_ms, error_rate_pct, cache_hit_rate_pct, prior_snapshot_id
        """
        if self._ambient_encoder is None:
            return None

        from aevum.core.ambient import (
            AmbientContextReceipt,
            _compute_system_state_hash,
        )

        model_identity_hash = str(env_signals.get("model_identity_hash", "UNKNOWN"))
        policy_version = str(env_signals.get("policy_version", "UNKNOWN"))
        tool_allowlist_hash = str(env_signals.get("tool_allowlist_hash", "UNKNOWN"))
        memory_store_hash = str(env_signals.get("memory_store_hash", "NONE"))

        system_state_hash = _compute_system_state_hash(
            model_identity_hash, policy_version, tool_allowlist_hash
        )

        snapshot = AmbientContextReceipt(
            snapshot_id=_uuid7(),
            session_id=session_id,
            captured_at=datetime.datetime.now(datetime.UTC).isoformat(),
            system_state_hash=system_state_hash,
            model_identity_hash=model_identity_hash,
            policy_version=policy_version,
            tool_allowlist_hash=tool_allowlist_hash,
            memory_store_hash=memory_store_hash,
            input_token_rate_per_min=env_signals.get("input_token_rate_per_min"),  # type: ignore[arg-type]
            output_token_rate_per_min=env_signals.get("output_token_rate_per_min"),  # type: ignore[arg-type]
            latency_p95_ms=env_signals.get("latency_p95_ms"),  # type: ignore[arg-type]
            error_rate_pct=env_signals.get("error_rate_pct"),  # type: ignore[arg-type]
            cache_hit_rate_pct=env_signals.get("cache_hit_rate_pct"),  # type: ignore[arg-type]
            trigger=trigger,
            prior_snapshot_id=env_signals.get("prior_snapshot_id"),  # type: ignore[arg-type]
        )

        return snapshot
