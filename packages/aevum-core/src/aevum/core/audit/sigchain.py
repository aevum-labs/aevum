# SPDX-License-Identifier: Apache-2.0
"""
Sigchain — the append-only, cryptographically chained episodic ledger for aevum-core.

In the aviation sense this is the flight data recorder (FDR): every event is signed,
every entry references the hash of its predecessor, and no entry may ever be modified
or deleted after it has been written (I1-APPEND_ONLY invariant).

Cryptographic primitives used throughout this module:
  Ed25519 (RFC 8032)  — primary per-event signature; 64-byte output, 32-byte key.
                        Fast, well-audited, and supported by all HSM vendors.
  SHA3-256 (FIPS 202) — both the per-entry payload hash and the chain-linkage hash.
                        SHA3 is based on the Keccak sponge, independent of SHA-2;
                        a SHA-2 collision would not compromise the chain hash.
  RFC 8785 JCS        — JSON Canonicalization Scheme: sort_keys=True + compact separators
                        produce identical bytes on every platform regardless of dict
                        insertion order, making signatures reproducible and verifiable.

Signing modes (see ADR-004 for trust-boundary analysis):
  InProcessSigner (default) — Ed25519 key lives in the same process as the agent.
    Sufficient for tamper-detection by a third party, but a compromised process could
    re-sign forged events. Use VaultTransitSigner for higher-trust deployments.
  DualSigner (optional, Phase 1) — adds ML-DSA-65 (CRYSTALS-Dilithium, FIPS 204 draft)
    as a belt-and-suspenders post-quantum second signature over the same canonical payload.

Spec reference: Section 06 (Episodic Ledger and Sigchain).
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
    from aevum.core.exceedance import ExceedanceDetector
    from aevum.core.signing import DualSigner
    from aevum.core.store import ReceiptStore
    from aevum.core.tsa import TSAClient

logger = logging.getLogger(__name__)

# GENESIS_HASH is the expected prior_hash of the very first chain entry (Spec Section 06).
# sha3_256(b"aevum:genesis") was chosen so that any independent validator can reproduce
# the correct starting sentinel without trusting the operator's stored state. A deterministic
# constant — not a randomly generated seed — is required so that cross-node chain verification
# can begin from the same known point regardless of when or where the chain was created.
GENESIS_HASH = hashlib.sha3_256(b"aevum:genesis").hexdigest()


class ImmutableLedgerError(Exception):
    """Raised when code attempts to modify or delete an audit chain entry.

    This exception enforces Barrier 4 — Audit Immutability (I1-APPEND_ONLY invariant).
    The episodic ledger is append-only by design: once an entry is written it cannot be
    overwritten, updated, or deleted. This error signals a permanent invariant violation,
    not a transient failure. Application code must not catch and suppress it — doing so
    would silently break the immutability guarantee that the entire sigchain depends on.
    """


def _uuid7() -> str:
    """Generate a UUID version 7 (time-ordered) identifier without an external dependency.

    UUID v7 is preferred over UUID v4 because its 48-bit millisecond-precision timestamp
    prefix enables natural temporal ordering of audit records by ID alone. This matters for
    chain reconstruction: events can be sorted without trusting the HLC system_time field —
    useful when replaying a chain from a dump or when system_time is unavailable.

    Bit layout follows draft-ietf-uuidrev-rfc4122bis §5.7: 48-bit Unix millisecond
    timestamp | version nibble 0x7 | 12-bit random_a | variant bits | 62-bit random_b.
    """
    ts_ms = int(time.time() * 1000) & 0xFFFFFFFFFFFF
    rand = int.from_bytes(os.urandom(10), "big")
    rand_a = (rand >> 62) & 0x0FFF
    rand_b = rand & 0x3FFFFFFFFFFFFFFF
    hi = (ts_ms << 16) | 0x7000 | rand_a
    lo = 0x8000000000000000 | rand_b
    h = f"{hi:016x}{lo:016x}"
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


class Sigchain:
    """Append-only Ed25519 signing chain; the in-process implementation of the sigchain spec.

    Each call to new_event() atomically increments the sequence counter, computes a
    SHA3-256 chain hash over the completed entry, and Ed25519-signs the canonical payload.
    The chain is a singly-linked list: every entry's prior_hash references the hash of its
    predecessor, and any modification to an entry breaks the chain from that point forward.

    Signing modes (trust-boundary analysis — see ADR-004):
      InProcessSigner (default) — Ed25519 key lives in the same process as the agent.
        A compromised process could re-sign forged events. Sufficient for tamper-detection
        by an independent third party; use VaultTransitSigner for higher-trust deployments.
      DualSigner (optional, Phase 1) — adds ML-DSA-65 post-quantum signature alongside the
        primary Ed25519 signature. Both cover the same canonical payload; both must verify
        for the entry to be considered intact.

    Optional constructor parameters (accumulated across development phases):
      signer / private_key / key_id  — signing key (defaults to InProcessSigner)
      dual_signer                    — Phase 1 post-quantum dual-sig
      tsa_client                     — Phase 1 RFC 3161 timestamp authority
      receipt_encoder                — Phase 1A COSE_Sign1 receipt encoding
      ambient_encoder                — Phase 1B ambient context snapshots
      receipt_store                  — Session 2 three-tier SQLite receipt storage
      exceedance_detector            — Session 3B FOQA per-session exceedance detection

    Do NOT refactor to a config object without an ADR-level decision.
    """

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
        # Session 2: receipt store — optional; stores COSE_Sign1 bytes after encoding
        receipt_store: ReceiptStore | None = None,
        # Session 3B: FOQA exceedance detector — optional, per-session, non-blocking
        exceedance_detector: ExceedanceDetector | None = None,
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
        self._receipt_store = receipt_store
        self._exceedance_detector = exceedance_detector

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
        """RFC 8785 JCS-canonicalize fields, SHA3-256 hash, Ed25519-sign; return url-safe base64."""
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
        """Append a new signed event to the chain and return the completed AuditEvent.

        Signing sequence:
          1. Increment sequence counter and assign a UUID v7 event_id.
          2. Compute SHA3-256(canonical_payload) as payload_hash (independently verifiable).
          3. Build signing_fields dict from all 16 identifying fields.
          4. RFC 8785 JCS canonicalise → SHA3-256 digest → Ed25519 sign (RFC 8032).
          5. If DualSigner is present: also sign with ML-DSA-65 and immediately verify
             both signatures (belt-and-suspenders — catches key corruption at write time,
             not at audit time when it would be too late to remediate).
          6. If TSAClient is present: request an RFC 3161 timestamp token (non-blocking —
             a TSA outage must never prevent audit events from being recorded).
          7. Advance self._prior_hash to SHA3-256(completed event fields).

        Returns:
            AuditEvent: The completed, signed, and chain-linked audit event.
        """
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
        # RFC 8785 JCS: sort_keys=True + compact separators ensure identical canonical bytes
        # across all Python versions and platforms regardless of dict insertion order.
        # SHA3-256 (FIPS 202) is then applied to those bytes, and the digest is Ed25519-signed
        # (RFC 8032). Signing the hash rather than the raw payload enables prehashed external
        # signing via HSMs or Vault transit without exposing the full canonical payload.
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

            # Circuit-breaker: TSA failures are caught and logged but never block the audit write.
            # A TSA outage must not prevent events from being recorded — the entry is written
            # without a timestamp token if the RFC 3161 authority is unreachable or rate-limited.
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

        # Session 2: store receipt blob and trigger escalation if applicable
        if self._receipt_store is not None and event.receipt_cbor is not None:
            try:
                receipt_hash = hashlib.sha3_256(event.receipt_cbor).hexdigest()
                self._receipt_store.put(
                    receipt_hash=receipt_hash,
                    blob=event.receipt_cbor,
                    entry_hash=event.payload_hash,
                    rekor_entry_ref="",
                    tier="operational",
                )
                try:
                    import cbor2

                    from aevum.core.escalation import escalate_if_triggered
                    from aevum.core.receipt import AevumReceipt
                    cose = cbor2.loads(event.receipt_cbor)
                    receipt_payload = cbor2.loads(cose[2])
                    receipt_obj = AevumReceipt.model_validate(receipt_payload)
                    escalate_if_triggered(
                        store=self._receipt_store,
                        receipt_hash=receipt_hash,
                        event_action=receipt_obj.action,
                        handoff_type=receipt_obj.handoff_type,
                        human_override_action=receipt_obj.human_override_action,
                        barrier_evaluations=receipt_obj.barrier_evaluations,
                    )
                except Exception as _e:
                    logger.warning("escalation check failed (non-blocking): %s", _e)
            except Exception as exc:
                logger.warning("receipt store.put() failed (non-blocking): %s", exc)

        # Session 3B: FOQA exceedance detection — optional, non-blocking
        if self._exceedance_detector is not None and event.receipt_cbor is not None:
            try:
                import cbor2

                from aevum.core.receipt import AevumReceipt
                cose = cbor2.loads(event.receipt_cbor)
                receipt = AevumReceipt.model_validate(cbor2.loads(cose[2]))
                self._exceedance_detector.process(receipt)
            except Exception as _e:
                logger.warning("exceedance detection failed (non-blocking): %s", _e)

        return event

    def verify_chain(self, events: list[AuditEvent]) -> bool:
        """Verify the entire chain from genesis. Returns True only if every entry is intact.

        An entry is "intact" when all of the following hold:
          1. prior_hash matches the expected value (GENESIS_HASH for the first entry, or the
             chain hash of the preceding entry for all subsequent entries).
          2. payload_hash matches SHA3-256(canonical_payload) — the payload was not modified.
          3. The Ed25519 signature (RFC 8032) verifies against SHA3-256(signing_fields).
          4. If DualSigner is present and the entry carries mldsa65_sig: the ML-DSA-65
             signature also verifies. Both must pass when present.

        A modification to any entry breaks the chain from that point forward because the
        next entry's prior_hash will no longer match. The verifier returns False as soon as
        any check fails — it does not attempt to isolate or skip the broken entry.

        Args:
            events: Ordered list of AuditEvent entries beginning at sequence=1.

        Returns:
            True if every entry passes every integrity check; False on first failure.
        """
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

        # Session 2: store ambient receipt if store is configured
        if self._receipt_store is not None:
            try:
                if self._ambient_encoder is not None:
                    ambient_cbor = self._ambient_encoder.encode(snapshot)
                else:
                    # Fall back to raw CBOR payload (not COSE_Sign1) with a warning
                    logger.warning(
                        "ambient_encoder not set but receipt_store is configured — "
                        "storing raw CBOR payload (not COSE_Sign1) for snapshot %s",
                        snapshot.snapshot_id,
                    )
                    ambient_cbor = snapshot.to_cbor_payload()
                self._receipt_store.put_ambient(
                    snapshot_id=snapshot.snapshot_id,
                    blob=ambient_cbor,
                    session_id=snapshot.session_id,
                    trigger=snapshot.trigger,
                )
            except Exception as exc:
                logger.warning("ambient receipt storage failed (non-blocking): %s", exc)

        return snapshot
