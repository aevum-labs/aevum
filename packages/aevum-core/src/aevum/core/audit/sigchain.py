"""
Sigchain — Ed25519 signing and SHA3-256 chaining. Spec Section 06.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
import time
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)

from aevum.core.audit.event import AuditEvent
from aevum.core.audit.hlc import now as hlc_now
from aevum.core.audit.signer import InProcessSigner, Signer

GENESIS_HASH = hashlib.sha3_256(b"aevum:genesis").hexdigest()


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
    """Per-node Ed25519 signing chain. Append-only by design."""

    def __init__(
        self,
        signer: Signer | None = None,
        # Backwards-compatible: wraps in InProcessSigner automatically
        private_key: object | None = None,  # Ed25519PrivateKey | None
        key_id: str | None = None,
        initial_sequence: int = 0,
        initial_prior_hash: str = GENESIS_HASH,
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
        signature = self._sign(signing_fields)

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
        )
        self._prior_hash = AuditEvent.hash_event_for_chain(event)
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
            try:
                sig_bytes = base64.urlsafe_b64decode(event.signature + "==")
                public_key.verify(sig_bytes, digest)
            except Exception:
                return False
            expected_prior = AuditEvent.hash_event_for_chain(event)
        return True
