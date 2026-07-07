# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
ReceiptEncoder — wraps Ed25519 (DualSigner) + TSAClient in a COSE_Sign1 envelope.

RFC 9052 §4.2 COSE_Sign1 structure:
  [protected_bstr, unprotected_map, payload_bstr, signature_bstr]

  protected header (CBOR map, then bstr-wrapped):
    {1: -8, 3: "application/aevum-receipt+cbor", 4: b"aevum-issuer-v1",
     15: {1: "did:web:<AEVUM_ISSUER_HOST>",
          2: "urn:aevum:receipt:<sigchain_entry_hash[:16]>",
          6: <int unix timestamp>}}
    alg -8 = EdDSA (Ed25519). NOT -7 (ECDSA/ES256).
    label 15 is the CWT_Claims map (draft-ietf-scitt-architecture-22 CDDL),
    keyed by RFC 8392 CWT claim numbers: 1=iss, 2=sub, 6=iat.

  unprotected header (plain CBOR map):
    {270: <tsa_token_bytes>}  if TSA succeeded and not dev mode
    label 270 is "3161-ctt" per RFC 9921 IANA Considerations — a Countersignature
    Timestamp Token. The TST's MessageImprint covers the COSE_Sign1 signature
    bytes (signature_bstr), not the payload. This is a deliberate CTT choice
    over TTC (RFC 9921 §1.1's suggested fit for SCITT-style notarization,
    label 269, protected header): TTC requires the TSA round-trip to complete
    *before* signing, which would either block receipt issuance on TSA
    availability or make the protected-header shape depend on whether the TSA
    responded in time. Both outcomes conflict with the existing "TSA outage
    never blocks a sigchain write" circuit-breaker contract (see tsa.py). CTT
    preserves that contract: the token is fetched non-blockingly after signing
    and simply omitted on failure.

  payload: AevumReceipt.to_cbor_payload() bytes

  signature: Ed25519 over SHA3-256(CBOR(Sig_Structure))
    Sig_Structure = ["Signature1", protected_bstr, b"", payload_bstr]
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from typing import TYPE_CHECKING, Any

import cbor2
from aevum.core.receipt import AevumReceipt

if TYPE_CHECKING:
    from aevum.core.audit.signer import Signer
    from aevum.core.tsa import TSAClient

logger = logging.getLogger(__name__)

# COSE algorithm identifier for EdDSA (Ed25519) per RFC 9053.
# -7 is ECDSA (ES256) — WRONG. -8 is EdDSA — CORRECT.
_COSE_ALG_EDDSA = -8

# RFC 9921 IANA Considerations: label 270 = "3161-ctt" (unprotected), the TST
# covers the COSE_Sign1 signature bytes. See module docstring for why CTT
# (not TTC, label 269/protected) was chosen for Aevum's per-entry receipts.
_COSE_CTT_LABEL = 270

# draft-ietf-scitt-architecture-22 CDDL: CWT_Claims map, protected label 15.
_COSE_CWT_CLAIMS_LABEL = 15
# RFC 8392 CBOR Web Token (CWT) Claims registry: iss=1, sub=2, iat=6.
_CWT_ISS = 1
_CWT_SUB = 2
_CWT_IAT = 6


def _build_protected_header(
    issuer_uri: str,
    subject_uri: str,
    issued_at: int,
) -> dict[Any, Any]:
    """Build the COSE_Sign1 protected header map with SCITT-profile fields."""
    return {
        1: _COSE_ALG_EDDSA,
        3: "application/aevum-receipt+cbor",
        4: b"aevum-issuer-v1",
        # SCITT-profile protected header field: CWT_Claims map (iss, sub, iat).
        # Decision: iat nests under label 15 as CWT claim 6, same as iss/sub,
        # rather than sitting flat at the top level. The CWT_Claims map exists
        # so a third-party SCITT verifier has exactly one place to look for
        # RFC 8392-registered claims; splitting iat out to a separate flat key
        # would recreate the two-location ambiguity that nesting iss/sub was
        # meant to avoid, for no compensating benefit. Safe to decide now: no
        # service persists ReceiptEncoder's output yet (receipt_encoder is an
        # unwired constructor param — see Sigchain.__init__ and
        # KNOWN_LIMITATIONS.md), so this is not yet a one-way format
        # commitment requiring a migration path.
        _COSE_CWT_CLAIMS_LABEL: {
            _CWT_ISS: issuer_uri,
            _CWT_SUB: subject_uri,
            _CWT_IAT: issued_at,
        },
    }


def _build_protected_bstr(
    issuer_uri: str,
    subject_uri: str,
    issued_at: int,
) -> bytes:
    """Return the bstr-wrapped CBOR encoding of the protected header."""
    return cbor2.dumps(_build_protected_header(issuer_uri, subject_uri, issued_at))


def _build_sig_structure(protected_bstr: bytes, payload_bstr: bytes) -> bytes:
    """
    Sig_Structure per RFC 9052 §4.4:
      ["Signature1", protected_bstr, external_aad, payload_bstr]
    external_aad is empty bytes for our use case.
    """
    return cbor2.dumps(["Signature1", protected_bstr, b"", payload_bstr])


class ReceiptEncoder:
    """
    Encodes an AevumReceipt as a COSE_Sign1 envelope.

    Uses the kernel's Ed25519 signing key (via Signer protocol) and optionally
    stamps the receipt with an RFC 3161 TSA token in the unprotected header.

    In dev_mode (AEVUM_DEV=1): no TSA calls, no network I/O.
    issuer_host: hostname for the SCITT iss field (did:web:<host>).
      Default: "aevum.local". Production: set AEVUM_ISSUER_HOST env var.
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

    def encode(self, receipt: AevumReceipt) -> bytes:
        """
        Encode an AevumReceipt as a COSE_Sign1 envelope.

        In dev_mode: no TSA call, no external network calls.
        Returns raw CBOR bytes of the 4-element COSE_Sign1 array.
        """
        issuer_uri = "did:web:" + self._issuer_host
        subject_uri = "urn:aevum:receipt:" + receipt.sigchain_entry_hash[:16]
        issued_at = int(time.time())

        protected_bstr = _build_protected_bstr(issuer_uri, subject_uri, issued_at)
        payload_bstr = receipt.to_cbor_payload()

        sig_structure = _build_sig_structure(protected_bstr, payload_bstr)
        digest = hashlib.sha3_256(sig_structure).digest()
        signature_bytes = self._signer.sign(digest)

        unprotected: dict[int, Any] = {}
        if not self._dev_mode and self._tsa_client is not None:
            try:
                # CTT (RFC 9921 label 270): timestamp the signature bytes, not the
                # payload — see module docstring for the TTC-vs-CTT tradeoff.
                tsa_token = self._tsa_client.timestamp(signature_bytes)
                if tsa_token is not None:
                    unprotected[_COSE_CTT_LABEL] = tsa_token.token_bytes
            except Exception as exc:  # noqa: BLE001
                logger.warning("ReceiptEncoder: TSA timestamp failed (non-blocking): %s", exc)

        cose_sign1 = [protected_bstr, unprotected, payload_bstr, signature_bytes]
        return cbor2.dumps(cose_sign1)

    @classmethod
    def decode_and_verify(
        cls,
        cose_bytes: bytes,
        verify_key: Any,  # nacl.signing.VerifyKey
    ) -> AevumReceipt:
        """
        Decode and verify a COSE_Sign1 receipt produced by encode().

        Returns AevumReceipt if the Ed25519 signature is valid.
        Raises ValueError on structural errors.
        Raises nacl.exceptions.BadSignatureError on invalid signature.
        """
        import hashlib

        try:
            cose = cbor2.loads(cose_bytes)
        except Exception as exc:
            raise ValueError(f"Cannot decode CBOR: {exc}") from exc

        if not isinstance(cose, list) or len(cose) != 4:
            raise ValueError(
                f"Expected COSE_Sign1 4-element array, got: {type(cose).__name__}"
            )

        protected_bstr, _unprotected, payload_bstr, signature_bytes = cose

        try:
            protected = cbor2.loads(protected_bstr)
        except Exception as exc:
            raise ValueError(f"Cannot decode COSE protected header: {exc}") from exc

        alg = protected.get(1) if isinstance(protected, dict) else None
        if alg != _COSE_ALG_EDDSA:
            raise ValueError(
                f"COSE_Sign1 algorithm rejected: expected EdDSA (-8), got {alg!r}. "
                "Aevum only accepts Ed25519 receipts."
            )

        sig_structure = _build_sig_structure(protected_bstr, payload_bstr)
        digest = hashlib.sha3_256(sig_structure).digest()

        # nacl raises BadSignatureError on invalid signature
        verify_key.verify(digest, bytes(signature_bytes))

        receipt_data = cbor2.loads(payload_bstr)
        return AevumReceipt.model_validate(receipt_data)

    @classmethod
    def from_env(cls) -> ReceiptEncoder:
        """
        Construct from environment variables.
        AEVUM_DEV=1 → dev_mode=True, no TSA client.
        AEVUM_ISSUER_HOST → issuer hostname for SCITT iss field (default: aevum.local).
        Otherwise: production InProcessSigner + TSAClient.
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
