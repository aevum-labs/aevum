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
  RFC 8785 JCS        — JSON Canonicalization Scheme via the rfc8785 library (not json.dumps):
                        UTF-8 with minimal Unicode escaping; floats forbidden; integers
                        > 2^53 forbidden; system_time serialised as a string (see signing_fields
                        in new_event). Produces identical bytes on every platform regardless
                        of dict insertion order, making signatures reproducible and verifiable.

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
import logging
import os
import time
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)

from aevum.core.audit.event import (
    AuditEvent,
    _build_signing_fields,
    _message_representative,
    build_principal_binding_blob,
    compute_principal_commitment,
    signing_fields_from_event,
    validate_principal_binding_sizes,
)
from aevum.core.audit.hlc import now as hlc_now
from aevum.core.audit.signer import InProcessSigner, Signer

# ML-DSA level suffix → OQS algorithm name. ml-dsa-87 is a one-line future add.
_MLDSA_LEVEL_MAP: dict[str, str] = {"ml-dsa-65": "ML-DSA-65"}

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
        # NOTE: wiring this into a service that persists its output is a one-way
        # format commitment — the protected/unprotected COSE header shape becomes
        # part of what's signed and stored. Any future change to that shape
        # (see aevum.publish.encoder's module docstring) then needs a real
        # migration path, not a direct edit, once receipts exist in the wild.
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
        """Canonicalize fields to message representative, SHA3-256, Ed25519-sign; return url-safe base64."""
        representative = _message_representative(fields)
        digest = hashlib.sha3_256(representative).digest()
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
        principal_identity: str | None = None,
        principal_claims: dict[str, Any] | None = None,
        commitment_key_id: str | None = None,
        commitment_key: bytes | None = None,
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

        P2-IDENTITY-V2 (DD2-DD7, spec aevum-signing-v2.md): passing commitment_key_id
        opts this entry into sig_format_version 2, signing three additional principal-
        binding fields that commit to a verified external credential identity (OIDC
        sub / SPIFFE ID / DID) rather than the plaintext actor field:
          principal_identity   — the bound credential identity; HMAC-committed, never
                                  stored in the clear (DD1).
          principal_claims     — verified credential claims; allow-list extracted into
                                  principal_binding (DD7) — never a bearer token, never
                                  the raw subject.
          commitment_key_id    — which CommitmentKeyStore key to attribute the
                                  commitment to; required to opt into v2 at all.
          commitment_key       — the actual key bytes, required only when
                                  principal_identity is also given (DD6: chain
                                  verification itself never needs this key — only
                                  identity-matching does).
        Omitting all four (the default) produces a v1 entry, byte-for-byte identical
        to pre-v2 behaviour.

        Returns:
            AuditEvent: The completed, signed, and chain-linked audit event.
        """
        validate_principal_binding_sizes(principal_identity, principal_claims)

        if commitment_key_id is not None:
            sig_format_version = 2
            if principal_identity is not None:
                if commitment_key is None:
                    raise ValueError(
                        "commitment_key is required when principal_identity is provided"
                    )
                principal_commitment = compute_principal_commitment(commitment_key, principal_identity)
            else:
                principal_commitment = None
            principal_binding = (
                build_principal_binding_blob(principal_claims) if principal_claims is not None else None
            )
        else:
            if principal_identity is not None or principal_claims is not None or commitment_key is not None:
                raise ValueError(
                    "commitment_key_id is required when principal_identity, "
                    "principal_claims, or commitment_key is provided"
                )
            sig_format_version = 1
            principal_commitment = None
            principal_binding = None

        self._sequence += 1
        event_id = _uuid7()
        ep_id = episode_id or _uuid7()
        vf = valid_from or datetime.datetime.now(datetime.UTC).isoformat()
        ts = hlc_now()
        payload_hash = AuditEvent.hash_payload(payload)
        prior = self._prior_hash
        # Derive scheme from signer — no literal "65" hardcoded here.
        scheme = f"ed25519+{self._dual_signer.scheme_suffix}" if self._dual_signer is not None else "ed25519"

        signing_fields = _build_signing_fields(
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
            payload_hash=payload_hash,
            prior_hash=prior,
            signer_key_id=self._signer.key_id,
            key_scheme=scheme,
            sig_format_version=sig_format_version,
            hash_alg="sha3-256",
            principal_binding=principal_binding,
            principal_commitment=principal_commitment,
            principal_commitment_key_id=commitment_key_id,
        )
        # True RFC 8785 canonicalization + domain prefix → message representative.
        # sha3_256(representative) is the Ed25519 signed digest AND the chain hash input —
        # compute-once: altering any signed field breaks signature verification and chain
        # linkage simultaneously.
        representative = _message_representative(signing_fields)
        signature = base64.urlsafe_b64encode(
            self._signer.sign(hashlib.sha3_256(representative).digest())
        ).rstrip(b"=").decode()

        # Phase 1: dual-sig + TSA (belt-and-suspenders, non-blocking)
        mldsa65_sig_hex: str | None = None
        mldsa65_pub_hex: str | None = None
        tsa_url: str | None = None
        tsa_token_hex: str | None = None

        if self._dual_signer is not None:
            try:
                from aevum.core.signing import DualSigner
                # ML-DSA signs the representative directly (not its hash).
                dual_sig = self._dual_signer.sign(representative)
                DualSigner.verify(representative, dual_sig)  # belt-and-suspenders at write time
                mldsa65_sig_hex = dual_sig.mldsa65_sig.hex()
                mldsa65_pub_hex = dual_sig.mldsa65_pub.hex()
            except Exception as exc:
                logger.error("Dual-sig failed on new chain entry: %s", exc)

        # Circuit-breaker: TSA failures are caught and logged but never block the audit write.
        # A TSA outage must not prevent events from being recorded — the entry is written
        # without a timestamp token if the RFC 3161 authority is unreachable or rate-limited.
        # TSA is independent of dual-sig posture — Ed25519-only deployments with a
        # configured tsa_client must still get a timestamp token (classical-only +
        # tsa_enabled=True is the Kernel.local() default; see kernel.py).
        if self._tsa_client is not None:
            try:
                tsa_token = self._tsa_client.timestamp(representative)
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
            mldsa65_sig=mldsa65_sig_hex,
            mldsa65_pub=mldsa65_pub_hex,
            tsa_url=tsa_url,
            tsa_token=tsa_token_hex,
            key_scheme=scheme,
            sig_format_version=sig_format_version,
            hash_alg="sha3-256",
            principal_binding=principal_binding,
            principal_commitment=principal_commitment,
            principal_commitment_key_id=commitment_key_id,
        )
        self._prior_hash = AuditEvent.hash_event_for_chain(event)

        # Phase 1A: attach COSE_Sign1 receipt bytes if encoder is configured
        if self._receipt_encoder is not None:
            try:
                from aevum.core.receipt import AevumReceipt
                # Wire escalation-relevant fields from the caller's payload through to
                # the receipt so should_escalate() (aevum.core.escalation) evaluates real
                # values instead of always defaulting to non-escalating.
                receipt = AevumReceipt.from_sigchain_event(
                    event,
                    handoff_type=payload.get("handoff_type"),
                    human_override_action=payload.get("human_override_action"),
                    barrier_evaluations=payload.get("barrier_evaluations", {}),
                )
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
                    cose = cbor2.loads(event.receipt_cbor, max_depth=400)
                    receipt_payload = cbor2.loads(cose[2], max_depth=400)
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
                cose = cbor2.loads(event.receipt_cbor, max_depth=400)
                receipt = AevumReceipt.model_validate(cbor2.loads(cose[2], max_depth=400))
                self._exceedance_detector.process(receipt)
            except Exception as _e:
                logger.warning("exceedance detection failed (non-blocking): %s", _e)

        return event

    def verify_chain(self, events: list[AuditEvent]) -> bool:
        """Verify the entire chain from genesis. Returns True only if every entry is intact.

        An entry is "intact" when all of the following hold:
          1. sig_format_version in {1, 2} (any other value, including None, is rejected),
             and never DECREASES across the chain (DD4) — a decrease is the fingerprint
             of a downgrade/splice attack, since stripping v2 fields to forge a v1 entry
             changes the signed bytes and breaks the signature without the private key
             (DD3); this pre-pass catches the cheaper case of an attacker splicing in a
             legitimately-signed-but-earlier-version entry from elsewhere in the chain.
          2. prior_hash matches the expected value (GENESIS_HASH for entry #1, or the chain
             hash of the preceding entry for all subsequent entries).
          3. payload_hash matches SHA3-256(canonical_payload).
          4. The Ed25519 signature verifies against SHA3-256(signing_fields) — 19 fields
             for sig_format_version 1, 22 fields (+ principal_binding/_commitment/
             _commitment_key_id) for sig_format_version 2 (DD2/DD4).
          5. key_scheme dispatch: "ed25519" → Ed25519 only; "ed25519+ml-dsa-65" → Ed25519
             AND ML-DSA-65 both required (absence = tamper/downgrade, fail closed).
          6. Homogeneity (D-S3): all entries share the same key_scheme; a mixed chain is the
             fingerprint of a downgrade or splice attack.

        Note (DD6): this method never needs a CommitmentKeyStore key — principal_commitment
        is opaque signed bytes to chain verification. Only identity-matching (confirming a
        specific external credential produced a given commitment) needs the key.

        Returns False on the first failing check — does not skip or isolate broken entries.
        """
        pub_key_bytes = self._signer.public_key_bytes()
        public_key = Ed25519PublicKey.from_public_bytes(pub_key_bytes)

        # Pre-pass 1 (DD4): every entry must declare sig_format_version in {1, 2}. None or
        # any other value is rejected immediately — no fallback, no legacy path.
        versions: list[int] = []
        for e in events:
            v = getattr(e, "sig_format_version", None)
            if v not in (1, 2):
                return False
            versions.append(v)

        # DD4 hardening: sig_format_version must never DECREASE across the chain.
        for prev_v, cur_v in zip(versions, versions[1:], strict=False):
            if cur_v < prev_v:
                return False

        # Pre-pass 2: homogeneity — all entries must share the same key_scheme.
        # Known limitation: mid-chain posture transitions are not supported in v0.8.0;
        # signed posture-change transitions are deferred to a later phase.
        if len({event.key_scheme for event in events}) > 1:
            return False

        expected_prior = GENESIS_HASH
        for event in events:
            if event.prior_hash != expected_prior:
                return False
            if AuditEvent.hash_payload(event.payload) != event.payload_hash:
                return False

            signing_fields = signing_fields_from_event(event)

            representative = _message_representative(signing_fields)
            digest = hashlib.sha3_256(representative).digest()

            try:
                sig_bytes = base64.urlsafe_b64decode(event.signature + "==")
                public_key.verify(sig_bytes, digest)
            except Exception:
                return False

            ks = event.key_scheme
            if ks == "ed25519":
                pass  # primary Ed25519 already verified above
            elif ks.startswith("ed25519+"):
                # Parse ML-DSA level from key_scheme suffix for level agility.
                # Unknown level → fail closed; never warn-and-fallback.
                level_suffix = ks[len("ed25519+"):]
                mldsa_alg = _MLDSA_LEVEL_MAP.get(level_suffix)
                if mldsa_alg is None:
                    return False  # unknown ML-DSA level
                # ML-DSA presence is REQUIRED — absence = tamper/downgrade attack.
                if event.mldsa65_sig is None or event.mldsa65_pub is None:
                    return False
                try:
                    from aevum.core.signing import DualSigner
                    # ML-DSA verifies against the representative (not its hash).
                    DualSigner.verify_mldsa(
                        representative,
                        bytes.fromhex(event.mldsa65_sig),
                        bytes.fromhex(event.mldsa65_pub),
                        alg=mldsa_alg,
                    )
                except Exception:
                    return False  # liboqs absent or invalid sig → fail closed
            else:
                return False  # unknown scheme: no warn-and-fallback

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
                else:  # pragma: no cover
                    # Dead code: the method-entry guard above (`if self._ambient_encoder
                    # is None: return None`) already guarantees self._ambient_encoder is
                    # not None by the time execution reaches here, and it is never
                    # reassigned within this method. Kept as defensive fallback in case
                    # that invariant changes; not reachable from any current call path
                    # (flagged HO-SESSION5-CLOSE / COV, not removed in this pass).
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
